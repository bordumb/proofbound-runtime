use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

const REPORT_SCHEMA: &str = "proofbound-runtime-plan-scaffold/1";
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEPENDENCIES: usize = 256;
const MAX_SEARCH_DIRECTORIES: usize = 256;
const MAX_SYMLINKS: usize = 40;
const MAX_STRING_TABLE_BYTES: usize = 8 * 1024 * 1024;
const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderFamily {
    Glibc,
    Musl,
}

#[derive(Clone, Debug)]
struct HostProfile {
    name: &'static str,
    architecture: Architecture,
    loader: LoaderFamily,
    default_directories: &'static [&'static str],
}

impl HostProfile {
    fn parse(value: &str) -> Result<Self, ScaffoldError> {
        match value {
            "linux-glibc-x86-64-v1" => Ok(Self {
                name: "linux-glibc-x86-64-v1",
                architecture: Architecture::X86_64,
                loader: LoaderFamily::Glibc,
                default_directories: &[
                    "/lib/x86_64-linux-gnu",
                    "/usr/lib/x86_64-linux-gnu",
                    "/lib64",
                    "/usr/lib64",
                    "/lib",
                    "/usr/lib",
                ],
            }),
            "linux-glibc-aarch64-v1" => Ok(Self {
                name: "linux-glibc-aarch64-v1",
                architecture: Architecture::Aarch64,
                loader: LoaderFamily::Glibc,
                default_directories: &[
                    "/lib/aarch64-linux-gnu",
                    "/usr/lib/aarch64-linux-gnu",
                    "/lib64",
                    "/usr/lib64",
                    "/lib",
                    "/usr/lib",
                ],
            }),
            "linux-musl-x86-64-v1" => Ok(Self {
                name: "linux-musl-x86-64-v1",
                architecture: Architecture::X86_64,
                loader: LoaderFamily::Musl,
                default_directories: &["/lib", "/usr/local/lib", "/usr/lib"],
            }),
            "linux-musl-aarch64-v1" => Ok(Self {
                name: "linux-musl-aarch64-v1",
                architecture: Architecture::Aarch64,
                loader: LoaderFamily::Musl,
                default_directories: &["/lib", "/usr/local/lib", "/usr/lib"],
            }),
            _ => Err(ScaffoldError::ProfileUnsupported),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScaffoldError {
    ExecutablePathInvalid,
    ExecutableReadFailed,
    ExecutableIdentityDrift,
    ElfInvalid,
    ElfArchitectureMismatch,
    ElfInterpreterMismatch,
    ElfDynamicInvalid,
    ProfileUnsupported,
    LoaderDataInvalid,
    DependencyMissing,
    DependencyIdentityDrift,
    BoundExceeded,
    Output,
}

impl ScaffoldError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ExecutablePathInvalid => "scaffold.executable.path-invalid",
            Self::ExecutableReadFailed => "scaffold.executable.read-failed",
            Self::ExecutableIdentityDrift => "scaffold.executable.identity-drift",
            Self::ElfInvalid => "scaffold.elf.invalid",
            Self::ElfArchitectureMismatch => "scaffold.elf.architecture-mismatch",
            Self::ElfInterpreterMismatch => "scaffold.elf.interpreter-mismatch",
            Self::ElfDynamicInvalid => "scaffold.elf.dynamic-invalid",
            Self::ProfileUnsupported => "scaffold.profile.unsupported",
            Self::LoaderDataInvalid => "scaffold.loader-data.invalid",
            Self::DependencyMissing => "scaffold.dependency.missing",
            Self::DependencyIdentityDrift => "scaffold.dependency.identity-drift",
            Self::BoundExceeded => "scaffold.bound.exceeded",
            Self::Output => "cli.output.write-failed",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct SymlinkHop {
    path: String,
    target: String,
}

#[derive(Clone, Debug, Serialize)]
struct Artifact {
    requested: String,
    resolved: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
    symlink_chain: Vec<SymlinkHop>,
}

#[derive(Clone, Debug, Serialize)]
struct Candidate {
    path: String,
    search_rule: String,
}

#[derive(Clone, Debug, Serialize)]
struct Dependency {
    soname: String,
    declared_by: String,
    selected: Artifact,
    search_rule: String,
    candidates: Vec<Candidate>,
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeRootSuggestion {
    path: String,
    provenance: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct OpenItem {
    code: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct ScaffoldReport {
    schema: &'static str,
    safe_policy: bool,
    host_profile: &'static str,
    executable: Artifact,
    interpreter: Option<Artifact>,
    resolution_inputs: Vec<Artifact>,
    dependencies: Vec<Dependency>,
    suggested_runtime_roots: Vec<RuntimeRootSuggestion>,
    open_items: Vec<OpenItem>,
}

#[derive(Clone, Debug, Default)]
struct DynamicInfo {
    interpreter: Option<PathBuf>,
    needed: Vec<String>,
    rpath: Vec<String>,
    runpath: Vec<String>,
    unsupported_tokens: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug)]
struct LoadSegment {
    offset: u64,
    virtual_address: u64,
    file_bytes: u64,
}

#[derive(Clone, Debug)]
struct QueueEntry {
    artifact: Artifact,
    info: DynamicInfo,
    inherited_rpath: Vec<PathBuf>,
}

pub(crate) fn execute(
    executable: &Path,
    profile: &str,
    output: &mut impl io::Write,
) -> Result<(), ScaffoldError> {
    let profile = HostProfile::parse(profile)?;
    let mut bytes_read = 0_u64;
    let (executable, bytes) = inspect_artifact(executable, true, &mut bytes_read)?;
    let root_info = parse_elf(&bytes, profile.architecture)?;
    require_interpreter_family(root_info.interpreter.as_deref(), profile.loader)?;

    let interpreter = root_info
        .interpreter
        .as_deref()
        .map(|path| inspect_artifact(path, true, &mut bytes_read).map(|(artifact, _)| artifact))
        .transpose()?;
    let cache = loader_cache(&profile, &mut bytes_read)?;
    let mut open_items = standard_open_items();
    if cache.unavailable {
        open_items.insert(OpenItem {
            code: "loader-data-unavailable".to_owned(),
            detail: "the selected host profile had no readable loader cache or musl path file"
                .to_owned(),
        });
    }
    for token in &root_info.unsupported_tokens {
        open_items.insert(OpenItem {
            code: "unsupported-dynamic-token".to_owned(),
            detail: token.clone(),
        });
    }

    let mut queue = VecDeque::from([QueueEntry {
        artifact: executable.clone(),
        info: root_info,
        inherited_rpath: Vec::new(),
    }]);
    let mut seen = BTreeSet::from([executable.resolved.clone()]);
    let mut dependencies = Vec::new();

    while let Some(parent) = queue.pop_front() {
        for soname in &parent.info.needed {
            if dependencies.len() >= MAX_DEPENDENCIES {
                return Err(ScaffoldError::BoundExceeded);
            }
            let candidates = search_candidates(&parent, soname, &profile, &cache, &mut open_items)?;
            let Some(first) = candidates.first() else {
                return Err(ScaffoldError::DependencyMissing);
            };
            if candidates.len() > 1 {
                open_items.insert(OpenItem {
                    code: "search-path-conflict".to_owned(),
                    detail: format!(
                        "{soname} has {} viable ordered candidates",
                        candidates.len()
                    ),
                });
            }
            let selected_path = PathBuf::from(&first.path);
            let (selected, selected_bytes) =
                inspect_artifact(&selected_path, false, &mut bytes_read)?;
            let info = parse_elf(&selected_bytes, profile.architecture)?;
            for token in &info.unsupported_tokens {
                open_items.insert(OpenItem {
                    code: "unsupported-dynamic-token".to_owned(),
                    detail: token.clone(),
                });
            }
            dependencies.push(Dependency {
                soname: soname.clone(),
                declared_by: parent.artifact.resolved.clone(),
                selected: selected.clone(),
                search_rule: first.search_rule.clone(),
                candidates,
            });
            if seen.insert(selected.resolved.clone()) {
                let mut inherited = parent.inherited_rpath.clone();
                if parent.info.runpath.is_empty() {
                    inherited.extend(expand_paths(
                        &parent.info.rpath,
                        Path::new(&parent.artifact.resolved),
                        &mut open_items,
                    )?);
                }
                queue.push_back(QueueEntry {
                    artifact: selected,
                    info,
                    inherited_rpath: deduplicate_paths(inherited),
                });
            }
        }
    }

    dependencies.sort_by(|left, right| {
        (&left.declared_by, &left.soname).cmp(&(&right.declared_by, &right.soname))
    });
    let suggested_runtime_roots = runtime_root_suggestions(interpreter.as_ref(), &dependencies)?;
    let report = ScaffoldReport {
        schema: REPORT_SCHEMA,
        safe_policy: false,
        host_profile: profile.name,
        executable,
        interpreter,
        resolution_inputs: cache.inputs,
        dependencies,
        suggested_runtime_roots,
        open_items: open_items.into_iter().collect(),
    };
    serde_json::to_writer(&mut *output, &report).map_err(|_| ScaffoldError::Output)?;
    writeln!(output).map_err(|_| ScaffoldError::Output)
}

#[derive(Default)]
struct LoaderCache {
    entries: BTreeMap<String, Vec<PathBuf>>,
    extra_directories: Vec<PathBuf>,
    inputs: Vec<Artifact>,
    unavailable: bool,
}

fn loader_cache(profile: &HostProfile, bytes_read: &mut u64) -> Result<LoaderCache, ScaffoldError> {
    match profile.loader {
        LoaderFamily::Glibc => glibc_cache(profile.architecture, bytes_read),
        LoaderFamily::Musl => musl_paths(profile.architecture, bytes_read),
    }
}

fn glibc_cache(
    architecture: Architecture,
    bytes_read: &mut u64,
) -> Result<LoaderCache, ScaffoldError> {
    let helper = ["/sbin/ldconfig", "/usr/sbin/ldconfig"]
        .iter()
        .map(Path::new)
        .find(|path| path.exists());
    let Some(helper) = helper else {
        return Ok(LoaderCache {
            unavailable: true,
            ..LoaderCache::default()
        });
    };
    let cache_path = Path::new("/etc/ld.so.cache");
    if !cache_path.exists() {
        return Ok(LoaderCache {
            unavailable: true,
            ..LoaderCache::default()
        });
    }
    let (helper, _) =
        inspect_artifact(helper, true, bytes_read).map_err(|_| ScaffoldError::LoaderDataInvalid)?;
    let (cache, _) = inspect_artifact(cache_path, false, bytes_read)
        .map_err(|_| ScaffoldError::LoaderDataInvalid)?;
    let output = Command::new(&helper.resolved)
        .arg("-p")
        .env_clear()
        .output()
        .map_err(|_| ScaffoldError::LoaderDataInvalid)?;
    if !output.status.success() || output.stdout.len() > MAX_STRING_TABLE_BYTES {
        return Err(ScaffoldError::LoaderDataInvalid);
    }
    let text =
        core::str::from_utf8(&output.stdout).map_err(|_| ScaffoldError::LoaderDataInvalid)?;
    let mut entries = BTreeMap::<String, Vec<PathBuf>>::new();
    for line in text.lines().skip(1) {
        let Some((left, path)) = line.split_once(" => ") else {
            continue;
        };
        let Some(soname) = left.split_ascii_whitespace().next() else {
            continue;
        };
        let qualifier = left.to_ascii_lowercase();
        let architecture_matches = match architecture {
            Architecture::X86_64 => qualifier.contains("x86-64") || qualifier.contains("x86_64"),
            Architecture::Aarch64 => qualifier.contains("aarch64"),
        };
        if !architecture_matches {
            continue;
        }
        let path = PathBuf::from(path.trim());
        if !path.is_absolute() || soname.contains('/') {
            return Err(ScaffoldError::LoaderDataInvalid);
        }
        entries.entry(soname.to_owned()).or_default().push(path);
    }
    Ok(LoaderCache {
        entries,
        inputs: vec![helper, cache],
        ..LoaderCache::default()
    })
}

fn musl_paths(
    architecture: Architecture,
    bytes_read: &mut u64,
) -> Result<LoaderCache, ScaffoldError> {
    let architecture = match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    };
    let path = PathBuf::from(format!("/etc/ld-musl-{architecture}.path"));
    if !path.exists() {
        return Ok(LoaderCache {
            unavailable: true,
            ..LoaderCache::default()
        });
    }
    let (input, bytes) =
        inspect_artifact(&path, false, bytes_read).map_err(|_| ScaffoldError::LoaderDataInvalid)?;
    let text = core::str::from_utf8(&bytes).map_err(|_| ScaffoldError::LoaderDataInvalid)?;
    let mut extra_directories = Vec::new();
    for entry in text.split([':', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let path = PathBuf::from(entry);
        if !path.is_absolute() {
            return Err(ScaffoldError::LoaderDataInvalid);
        }
        extra_directories.push(path);
    }
    Ok(LoaderCache {
        extra_directories: deduplicate_paths(extra_directories),
        inputs: vec![input],
        ..LoaderCache::default()
    })
}

fn search_candidates(
    parent: &QueueEntry,
    soname: &str,
    profile: &HostProfile,
    cache: &LoaderCache,
    open_items: &mut BTreeSet<OpenItem>,
) -> Result<Vec<Candidate>, ScaffoldError> {
    let object = Path::new(&parent.artifact.resolved);
    let mut search = Vec::new();
    let dynamic_paths = if parent.info.runpath.is_empty() {
        &parent.info.rpath
    } else {
        &parent.info.runpath
    };
    let rule = if parent.info.runpath.is_empty() {
        "elf-rpath"
    } else {
        "elf-runpath"
    };
    for path in expand_paths(dynamic_paths, object, open_items)? {
        search.push((path, rule.to_owned()));
    }
    for path in &parent.inherited_rpath {
        search.push((path.clone(), "inherited-rpath".to_owned()));
    }
    if let Some(paths) = cache.entries.get(soname) {
        for path in paths {
            search.push((path.clone(), "glibc-loader-cache-exact".to_owned()));
        }
    }
    for path in &cache.extra_directories {
        search.push((path.clone(), "musl-path-file".to_owned()));
    }
    for path in profile.default_directories {
        search.push((PathBuf::from(path), "profile-default".to_owned()));
    }
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for (path, rule) in search {
        let candidate = if rule == "glibc-loader-cache-exact" {
            path
        } else {
            path.join(soname)
        };
        if seen.insert(candidate.clone()) && fs::metadata(&candidate).is_ok() {
            candidates.push(Candidate {
                path: path_text(&candidate)?,
                search_rule: rule,
            });
        }
    }
    if candidates.len() > MAX_SEARCH_DIRECTORIES {
        return Err(ScaffoldError::BoundExceeded);
    }
    Ok(candidates)
}

fn expand_paths(
    entries: &[String],
    object: &Path,
    open_items: &mut BTreeSet<OpenItem>,
) -> Result<Vec<PathBuf>, ScaffoldError> {
    let origin = object.parent().ok_or(ScaffoldError::ElfDynamicInvalid)?;
    let mut paths = Vec::new();
    for entry in entries {
        let expanded = entry
            .replace("${ORIGIN}", &path_text(origin)?)
            .replace("$ORIGIN", &path_text(origin)?);
        if expanded.contains('$') {
            open_items.insert(OpenItem {
                code: "unsupported-dynamic-token".to_owned(),
                detail: entry.clone(),
            });
            continue;
        }
        let path = PathBuf::from(expanded);
        if path.is_absolute() {
            paths.push(path);
        } else {
            open_items.insert(OpenItem {
                code: "relative-search-path".to_owned(),
                detail: entry.clone(),
            });
        }
    }
    Ok(deduplicate_paths(paths))
}

fn standard_open_items() -> BTreeSet<OpenItem> {
    [
        ("choose-write-roots", "choose every writable root"),
        (
            "choose-environment",
            "choose every inherited environment variable name",
        ),
        (
            "choose-limits",
            "choose wall-time, process, output, memory, and swap limits",
        ),
        ("choose-network-mode", "choose the Runtime network profile"),
        (
            "dynamic-loads-unresolved",
            "review plugins, language packages, and runtime dlopen calls",
        ),
        (
            "configuration-unresolved",
            "review configuration and environment-dependent searches",
        ),
    ]
    .into_iter()
    .map(|(code, detail)| OpenItem {
        code: code.to_owned(),
        detail: detail.to_owned(),
    })
    .collect()
}

fn runtime_root_suggestions(
    interpreter: Option<&Artifact>,
    dependencies: &[Dependency],
) -> Result<Vec<RuntimeRootSuggestion>, ScaffoldError> {
    let mut roots = BTreeMap::<String, BTreeSet<String>>::new();
    if let Some(interpreter) = interpreter {
        let parent = Path::new(&interpreter.resolved)
            .parent()
            .ok_or(ScaffoldError::ElfDynamicInvalid)?;
        roots
            .entry(path_text(parent)?)
            .or_default()
            .insert("ELF PT_INTERP".to_owned());
    }
    for dependency in dependencies {
        let parent = Path::new(&dependency.selected.resolved)
            .parent()
            .ok_or(ScaffoldError::ElfDynamicInvalid)?;
        roots.entry(path_text(parent)?).or_default().insert(format!(
            "{} required by {} via {}",
            dependency.soname, dependency.declared_by, dependency.search_rule
        ));
    }
    Ok(roots
        .into_iter()
        .map(|(path, provenance)| RuntimeRootSuggestion {
            path,
            provenance: provenance.into_iter().collect(),
        })
        .collect())
}

fn inspect_artifact(
    requested: &Path,
    executable: bool,
    bytes_read: &mut u64,
) -> Result<(Artifact, Vec<u8>), ScaffoldError> {
    if !requested.is_absolute()
        || requested
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(ScaffoldError::ExecutablePathInvalid);
    }
    let (resolved, symlink_chain) = resolve_symlinks(requested)?;
    let mut file = File::open(&resolved).map_err(|_| ScaffoldError::ExecutableReadFailed)?;
    let before = file
        .metadata()
        .map_err(|_| ScaffoldError::ExecutableReadFailed)?;
    if !before.is_file()
        || before.len() > MAX_FILE_BYTES
        || executable && before.permissions().mode() & 0o111 == 0
    {
        return Err(ScaffoldError::ExecutableReadFailed);
    }
    *bytes_read = bytes_read
        .checked_add(before.len())
        .filter(|total| *total <= MAX_TOTAL_BYTES)
        .ok_or(ScaffoldError::BoundExceeded)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| ScaffoldError::BoundExceeded)?,
    );
    file.read_to_end(&mut bytes)
        .map_err(|_| ScaffoldError::ExecutableReadFailed)?;
    let after = file
        .metadata()
        .map_err(|_| ScaffoldError::ExecutableIdentityDrift)?;
    let path_after = fs::metadata(&resolved).map_err(|_| ScaffoldError::ExecutableIdentityDrift)?;
    if metadata_changed(&before, &after)
        || metadata_changed(&after, &path_after)
        || bytes.len() as u64 != after.len()
    {
        return Err(if executable {
            ScaffoldError::ExecutableIdentityDrift
        } else {
            ScaffoldError::DependencyIdentityDrift
        });
    }
    let sha256 = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
    Ok((
        Artifact {
            requested: path_text(requested)?,
            resolved: path_text(&resolved)?,
            sha256,
            size_bytes: after.len(),
            mode: format!("{:04o}", after.permissions().mode() & 0o7777),
            symlink_chain,
        },
        bytes,
    ))
}

fn metadata_changed(left: &Metadata, right: &Metadata) -> bool {
    left.dev() != right.dev()
        || left.ino() != right.ino()
        || left.len() != right.len()
        || left.mode() != right.mode()
        || left.mtime() != right.mtime()
        || left.mtime_nsec() != right.mtime_nsec()
        || left.ctime() != right.ctime()
        || left.ctime_nsec() != right.ctime_nsec()
}

fn resolve_symlinks(path: &Path) -> Result<(PathBuf, Vec<SymlinkHop>), ScaffoldError> {
    let mut remaining = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_os_string()),
            Component::RootDir => None,
            _ => None,
        })
        .collect::<VecDeque<_>>();
    let mut current = PathBuf::from("/");
    let mut chain = Vec::new();
    let mut visited = BTreeSet::new();
    while let Some(component) = remaining.pop_front() {
        current.push(component);
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| ScaffoldError::ExecutableReadFailed)?;
        if !metadata.file_type().is_symlink() {
            continue;
        }
        if chain.len() >= MAX_SYMLINKS || !visited.insert(current.clone()) {
            return Err(ScaffoldError::ExecutablePathInvalid);
        }
        let target = fs::read_link(&current).map_err(|_| ScaffoldError::ExecutableReadFailed)?;
        chain.push(SymlinkHop {
            path: path_text(&current)?,
            target: path_text(&target)?,
        });
        let parent = current
            .parent()
            .ok_or(ScaffoldError::ExecutablePathInvalid)?;
        let target = if target.is_absolute() {
            target
        } else {
            parent.join(target)
        };
        let mut combined = normalize_absolute(&target)?
            .components()
            .filter_map(|part| match part {
                Component::Normal(value) => Some(value.to_os_string()),
                _ => None,
            })
            .collect::<VecDeque<_>>();
        combined.extend(remaining);
        remaining = combined;
        current = PathBuf::from("/");
    }
    Ok((current, chain))
}

fn normalize_absolute(path: &Path) -> Result<PathBuf, ScaffoldError> {
    if !path.is_absolute() {
        return Err(ScaffoldError::ExecutablePathInvalid);
    }
    let mut parts = Vec::<OsString>::new();
    for component in path.components() {
        match component {
            Component::RootDir => parts.clear(),
            Component::Normal(value) => parts.push(value.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop().ok_or(ScaffoldError::ExecutablePathInvalid)?;
            }
            Component::Prefix(_) => return Err(ScaffoldError::ExecutablePathInvalid),
        }
    }
    let mut result = PathBuf::from("/");
    result.extend(parts);
    Ok(result)
}

fn path_text(path: &Path) -> Result<String, ScaffoldError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(ScaffoldError::ExecutablePathInvalid)
}

fn require_interpreter_family(
    interpreter: Option<&Path>,
    family: LoaderFamily,
) -> Result<(), ScaffoldError> {
    let Some(interpreter) = interpreter else {
        return Ok(());
    };
    let name = interpreter
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ScaffoldError::ElfInterpreterMismatch)?;
    let matches = match family {
        LoaderFamily::Glibc => name.starts_with("ld-linux") || name.starts_with("ld64.so"),
        LoaderFamily::Musl => name.starts_with("ld-musl-") && name.ends_with(".so.1"),
    };
    if matches {
        Ok(())
    } else {
        Err(ScaffoldError::ElfInterpreterMismatch)
    }
}

fn parse_elf(bytes: &[u8], architecture: Architecture) -> Result<DynamicInfo, ScaffoldError> {
    let header = bytes
        .get(..ELF_HEADER_BYTES)
        .ok_or(ScaffoldError::ElfInvalid)?;
    if header.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || read_u16(header, 52)? != ELF_HEADER_BYTES as u16
        || usize::from(read_u16(header, 54)?) < PROGRAM_HEADER_BYTES
    {
        return Err(ScaffoldError::ElfInvalid);
    }
    let expected_machine = match architecture {
        Architecture::X86_64 => 62,
        Architecture::Aarch64 => 183,
    };
    if read_u16(header, 18)? != expected_machine {
        return Err(ScaffoldError::ElfArchitectureMismatch);
    }
    let table_offset =
        usize::try_from(read_u64(header, 32)?).map_err(|_| ScaffoldError::ElfInvalid)?;
    let entry_size = usize::from(read_u16(header, 54)?);
    let entry_count = usize::from(read_u16(header, 56)?);
    let table_bytes = entry_size
        .checked_mul(entry_count)
        .filter(|size| *size <= MAX_STRING_TABLE_BYTES)
        .ok_or(ScaffoldError::BoundExceeded)?;
    let table = bytes
        .get(table_offset..table_offset + table_bytes)
        .ok_or(ScaffoldError::ElfInvalid)?;
    let mut interpreter = None;
    let mut dynamic = None;
    let mut loads = Vec::new();
    for index in 0..entry_count {
        let entry = table
            .get(index * entry_size..index * entry_size + PROGRAM_HEADER_BYTES)
            .ok_or(ScaffoldError::ElfInvalid)?;
        match read_u32(entry, 0)? {
            1 => loads.push(LoadSegment {
                offset: read_u64(entry, 8)?,
                virtual_address: read_u64(entry, 16)?,
                file_bytes: read_u64(entry, 32)?,
            }),
            2 => {
                if dynamic.is_some() {
                    return Err(ScaffoldError::ElfDynamicInvalid);
                }
                dynamic = Some((read_u64(entry, 8)?, read_u64(entry, 32)?));
            }
            3 => {
                if interpreter.is_some() {
                    return Err(ScaffoldError::ElfInvalid);
                }
                let offset =
                    usize::try_from(read_u64(entry, 8)?).map_err(|_| ScaffoldError::ElfInvalid)?;
                let size =
                    usize::try_from(read_u64(entry, 32)?).map_err(|_| ScaffoldError::ElfInvalid)?;
                let raw = bytes
                    .get(offset..offset + size)
                    .ok_or(ScaffoldError::ElfInvalid)?;
                let Some((&0, text)) = raw.split_last() else {
                    return Err(ScaffoldError::ElfInvalid);
                };
                if text.is_empty() || text.contains(&0) {
                    return Err(ScaffoldError::ElfInvalid);
                }
                let text = core::str::from_utf8(text).map_err(|_| ScaffoldError::ElfInvalid)?;
                let path = PathBuf::from(text);
                if !path.is_absolute() {
                    return Err(ScaffoldError::ElfInvalid);
                }
                interpreter = Some(path);
            }
            _ => {}
        }
    }
    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Ok(DynamicInfo {
            interpreter,
            ..DynamicInfo::default()
        });
    };
    let start = usize::try_from(dynamic_offset).map_err(|_| ScaffoldError::ElfDynamicInvalid)?;
    let size = usize::try_from(dynamic_size).map_err(|_| ScaffoldError::ElfDynamicInvalid)?;
    if size % 16 != 0 || size > MAX_STRING_TABLE_BYTES {
        return Err(ScaffoldError::ElfDynamicInvalid);
    }
    let entries = bytes
        .get(start..start + size)
        .ok_or(ScaffoldError::ElfDynamicInvalid)?;
    let mut string_address = None;
    let mut string_size = None;
    let mut needed = Vec::new();
    let mut rpath = None;
    let mut runpath = None;
    for entry in entries.chunks_exact(16) {
        let tag = read_u64(entry, 0)?;
        let value = read_u64(entry, 8)?;
        match tag {
            0 => break,
            1 => needed.push(value),
            5 => string_address = Some(value),
            10 => string_size = Some(value),
            15 => rpath = Some(value),
            29 => runpath = Some(value),
            _ => {}
        }
    }
    let string_address = string_address.ok_or(ScaffoldError::ElfDynamicInvalid)?;
    let string_size = usize::try_from(string_size.ok_or(ScaffoldError::ElfDynamicInvalid)?)
        .map_err(|_| ScaffoldError::ElfDynamicInvalid)?;
    if string_size == 0 || string_size > MAX_STRING_TABLE_BYTES {
        return Err(ScaffoldError::ElfDynamicInvalid);
    }
    let string_offset = loads
        .iter()
        .find_map(|segment| {
            let end = segment.virtual_address.checked_add(segment.file_bytes)?;
            if (segment.virtual_address..end).contains(&string_address) {
                segment
                    .offset
                    .checked_add(string_address - segment.virtual_address)
            } else {
                None
            }
        })
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(ScaffoldError::ElfDynamicInvalid)?;
    let strings = bytes
        .get(string_offset..string_offset + string_size)
        .ok_or(ScaffoldError::ElfDynamicInvalid)?;
    let needed = needed
        .into_iter()
        .map(|offset| dynamic_string(strings, offset))
        .collect::<Result<Vec<_>, _>>()?;
    if needed.iter().any(|name| name.contains('/')) {
        return Err(ScaffoldError::ElfDynamicInvalid);
    }
    let rpath = rpath
        .map(|offset| dynamic_paths(strings, offset))
        .transpose()?
        .unwrap_or_default();
    let runpath = runpath
        .map(|offset| dynamic_paths(strings, offset))
        .transpose()?
        .unwrap_or_default();
    let unsupported_tokens = rpath
        .iter()
        .chain(&runpath)
        .filter(|path| {
            let stripped = path.replace("${ORIGIN}", "").replace("$ORIGIN", "");
            stripped.contains('$')
        })
        .cloned()
        .collect();
    Ok(DynamicInfo {
        interpreter,
        needed,
        rpath,
        runpath,
        unsupported_tokens,
    })
}

fn dynamic_string(strings: &[u8], offset: u64) -> Result<String, ScaffoldError> {
    let offset = usize::try_from(offset).map_err(|_| ScaffoldError::ElfDynamicInvalid)?;
    let tail = strings
        .get(offset..)
        .ok_or(ScaffoldError::ElfDynamicInvalid)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ScaffoldError::ElfDynamicInvalid)?;
    if end == 0 {
        return Err(ScaffoldError::ElfDynamicInvalid);
    }
    core::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| ScaffoldError::ElfDynamicInvalid)
}

fn dynamic_paths(strings: &[u8], offset: u64) -> Result<Vec<String>, ScaffoldError> {
    Ok(dynamic_string(strings, offset)?
        .split(':')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ScaffoldError> {
    let bytes = bytes
        .get(offset..offset + 2)
        .ok_or(ScaffoldError::ElfInvalid)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ScaffoldError> {
    let bytes = bytes
        .get(offset..offset + 4)
        .ok_or(ScaffoldError::ElfInvalid)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ScaffoldError> {
    let bytes = bytes
        .get(offset..offset + 8)
        .ok_or(ScaffoldError::ElfInvalid)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn deduplicate_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureRoot(PathBuf);

    impl FixtureRoot {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "pbr-scaffold-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("create fixture root");
            Self(root)
        }

        fn write(&self, relative: &str, bytes: &[u8], executable: bool) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("fixture has parent"))
                .expect("create fixture parent");
            fs::write(&path, bytes).expect("write fixture");
            let mode = if executable { 0o755 } else { 0o644 };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
            path
        }
    }

    impl Drop for FixtureRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn static_elf(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; ELF_HEADER_BYTES];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[52..54].copy_from_slice(&(ELF_HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes
    }

    fn dynamic_elf(
        interpreter: &str,
        needed: &[&str],
        runpath: Option<&str>,
        machine: u16,
    ) -> Vec<u8> {
        let phoff = ELF_HEADER_BYTES;
        let phnum = 3_usize;
        let interp_offset = phoff + phnum * PROGRAM_HEADER_BYTES;
        let interp = format!("{interpreter}\0").into_bytes();
        let dynamic_offset = interp_offset + interp.len();
        let mut strings = vec![0_u8];
        let needed_offsets = needed
            .iter()
            .map(|name| {
                let offset = strings.len() as u64;
                strings.extend_from_slice(name.as_bytes());
                strings.push(0);
                offset
            })
            .collect::<Vec<_>>();
        let runpath_offset = runpath.map(|path| {
            let offset = strings.len() as u64;
            strings.extend_from_slice(path.as_bytes());
            strings.push(0);
            offset
        });
        let dynamic_entries = 3 + needed_offsets.len() + usize::from(runpath.is_some());
        let dynamic_size = dynamic_entries * 16;
        let strings_offset = dynamic_offset + dynamic_size;
        let base = 0x400000_u64;
        let total = strings_offset + strings.len();
        let mut bytes = static_elf(machine);
        bytes.resize(total, 0);
        bytes[32..40].copy_from_slice(&(phoff as u64).to_le_bytes());
        bytes[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
        let load = phoff;
        bytes[load..load + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[load + 16..load + 24].copy_from_slice(&base.to_le_bytes());
        bytes[load + 32..load + 40].copy_from_slice(&(total as u64).to_le_bytes());
        let interp_header = phoff + PROGRAM_HEADER_BYTES;
        bytes[interp_header..interp_header + 4].copy_from_slice(&3_u32.to_le_bytes());
        bytes[interp_header + 8..interp_header + 16]
            .copy_from_slice(&(interp_offset as u64).to_le_bytes());
        bytes[interp_header + 32..interp_header + 40]
            .copy_from_slice(&(interp.len() as u64).to_le_bytes());
        let dynamic_header = interp_header + PROGRAM_HEADER_BYTES;
        bytes[dynamic_header..dynamic_header + 4].copy_from_slice(&2_u32.to_le_bytes());
        bytes[dynamic_header + 8..dynamic_header + 16]
            .copy_from_slice(&(dynamic_offset as u64).to_le_bytes());
        bytes[dynamic_header + 32..dynamic_header + 40]
            .copy_from_slice(&(dynamic_size as u64).to_le_bytes());
        bytes[interp_offset..interp_offset + interp.len()].copy_from_slice(&interp);
        let mut cursor = dynamic_offset;
        for offset in needed_offsets {
            write_dynamic(&mut bytes, &mut cursor, 1, offset);
        }
        write_dynamic(&mut bytes, &mut cursor, 5, base + strings_offset as u64);
        write_dynamic(&mut bytes, &mut cursor, 10, strings.len() as u64);
        if let Some(offset) = runpath_offset {
            write_dynamic(&mut bytes, &mut cursor, 29, offset);
        }
        write_dynamic(&mut bytes, &mut cursor, 0, 0);
        bytes[strings_offset..].copy_from_slice(&strings);
        bytes
    }

    fn write_dynamic(bytes: &mut [u8], cursor: &mut usize, tag: u64, value: u64) {
        bytes[*cursor..*cursor + 8].copy_from_slice(&tag.to_le_bytes());
        bytes[*cursor + 8..*cursor + 16].copy_from_slice(&value.to_le_bytes());
        *cursor += 16;
    }

    #[test]
    fn static_elf_has_no_inferred_runtime_closure() {
        let info = parse_elf(&static_elf(62), Architecture::X86_64).expect("static ELF parses");
        assert!(info.interpreter.is_none());
        assert!(info.needed.is_empty());
    }

    #[test]
    fn glibc_dynamic_metadata_is_parsed_without_execution() {
        let bytes = dynamic_elf(
            "/lib64/ld-linux-x86-64.so.2",
            &["libc.so.6", "libm.so.6"],
            Some("$ORIGIN/lib:/vendor/lib"),
            62,
        );
        let info = parse_elf(&bytes, Architecture::X86_64).expect("dynamic ELF parses");
        assert_eq!(
            info.interpreter,
            Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2"))
        );
        assert_eq!(info.needed, ["libc.so.6", "libm.so.6"]);
        assert_eq!(info.runpath, ["$ORIGIN/lib", "/vendor/lib"]);
    }

    #[test]
    fn musl_interpreter_is_distinct_from_glibc() {
        let bytes = dynamic_elf("/lib/ld-musl-x86_64.so.1", &[], None, 62);
        let info = parse_elf(&bytes, Architecture::X86_64).expect("musl ELF parses");
        assert!(
            require_interpreter_family(info.interpreter.as_deref(), LoaderFamily::Musl).is_ok()
        );
        assert_eq!(
            require_interpreter_family(info.interpreter.as_deref(), LoaderFamily::Glibc),
            Err(ScaffoldError::ElfInterpreterMismatch)
        );
    }

    #[test]
    fn wrong_architecture_fails_closed() {
        assert_eq!(
            parse_elf(&static_elf(183), Architecture::X86_64).unwrap_err(),
            ScaffoldError::ElfArchitectureMismatch
        );
    }

    #[test]
    fn unsupported_search_token_stays_open() {
        let bytes = dynamic_elf(
            "/lib64/ld-linux-x86-64.so.2",
            &["libc.so.6"],
            Some("$LIB:/opt/lib"),
            62,
        );
        let info = parse_elf(&bytes, Architecture::X86_64).expect("metadata parses");
        assert_eq!(info.unsupported_tokens, BTreeSet::from(["$LIB".to_owned()]));
    }

    #[test]
    fn missing_and_conflicting_dependencies_have_distinct_contracts() {
        assert_ne!(
            ScaffoldError::DependencyMissing.code(),
            "search-path-conflict"
        );
        assert!(
            standard_open_items()
                .iter()
                .any(|item| item.code == "dynamic-loads-unresolved")
        );
    }

    #[test]
    fn symlink_cycles_are_rejected() {
        let root = std::env::temp_dir().join(format!("pbr-scaffold-cycle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create fixture");
        std::os::unix::fs::symlink("b", root.join("a")).expect("first link");
        std::os::unix::fs::symlink("a", root.join("b")).expect("second link");
        assert_eq!(
            resolve_symlinks(&root.join("a")).unwrap_err(),
            ScaffoldError::ExecutablePathInvalid
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn identity_drift_has_a_separate_failure_code() {
        assert_ne!(
            ScaffoldError::ExecutableIdentityDrift.code(),
            ScaffoldError::DependencyIdentityDrift.code()
        );
    }

    #[test]
    fn full_glibc_closure_is_resolved_with_provenance() {
        let root = FixtureRoot::new("glibc");
        let interpreter = root.write("ld-linux-x86-64.so.2", &static_elf(62), true);
        root.write("lib/libsecond.so", &static_elf(62), false);
        root.write(
            "lib/libfirst.so",
            &dynamic_elf(
                interpreter.to_str().expect("UTF-8 fixture"),
                &["libsecond.so"],
                Some("$ORIGIN"),
                62,
            ),
            false,
        );
        let executable = root.write(
            "program",
            &dynamic_elf(
                interpreter.to_str().expect("UTF-8 fixture"),
                &["libfirst.so"],
                Some("$ORIGIN/lib"),
                62,
            ),
            true,
        );
        let mut output = Vec::new();
        execute(&executable, "linux-glibc-x86-64-v1", &mut output)
            .expect("glibc closure scaffolds");
        let report: serde_json::Value = serde_json::from_slice(&output).expect("JSON report");
        assert_eq!(report["safe_policy"], false);
        assert_eq!(report["dependencies"].as_array().unwrap().len(), 2);
        assert!(
            report["suggested_runtime_roots"]
                .as_array()
                .unwrap()
                .iter()
                .all(|root| !root["provenance"].as_array().unwrap().is_empty())
        );
    }

    #[test]
    fn full_musl_closure_is_resolved_with_provenance() {
        let root = FixtureRoot::new("musl");
        let interpreter = root.write("ld-musl-x86_64.so.1", &static_elf(62), true);
        root.write("lib/libfixture-musl.so", &static_elf(62), false);
        let executable = root.write(
            "program",
            &dynamic_elf(
                interpreter.to_str().expect("UTF-8 fixture"),
                &["libfixture-musl.so"],
                Some("$ORIGIN/lib"),
                62,
            ),
            true,
        );
        let mut output = Vec::new();
        execute(&executable, "linux-musl-x86-64-v1", &mut output).expect("musl closure scaffolds");
        let report: serde_json::Value = serde_json::from_slice(&output).expect("JSON report");
        assert_eq!(report["dependencies"][0]["soname"], "libfixture-musl.so");
        assert_eq!(report["dependencies"][0]["search_rule"], "elf-runpath");
    }

    #[test]
    fn missing_library_fails_closed() {
        let root = FixtureRoot::new("missing");
        let interpreter = root.write("ld-linux-x86-64.so.2", &static_elf(62), true);
        let executable = root.write(
            "program",
            &dynamic_elf(
                interpreter.to_str().expect("UTF-8 fixture"),
                &["lib-proofbound-definitely-missing.so"],
                Some("$ORIGIN/lib"),
                62,
            ),
            true,
        );
        assert_eq!(
            execute(&executable, "linux-glibc-x86-64-v1", &mut Vec::new()),
            Err(ScaffoldError::DependencyMissing)
        );
    }

    #[test]
    fn ordered_conflicts_are_reported_not_hidden() {
        let root = FixtureRoot::new("conflict");
        let interpreter = root.write("ld-linux-x86-64.so.2", &static_elf(62), true);
        root.write("first/libconflict.so", &static_elf(62), false);
        root.write("second/libconflict.so", &static_elf(62), false);
        let executable = root.write(
            "program",
            &dynamic_elf(
                interpreter.to_str().expect("UTF-8 fixture"),
                &["libconflict.so"],
                Some("$ORIGIN/first:$ORIGIN/second"),
                62,
            ),
            true,
        );
        let mut output = Vec::new();
        execute(&executable, "linux-glibc-x86-64-v1", &mut output)
            .expect("ordered conflict remains reviewable");
        let report: serde_json::Value = serde_json::from_slice(&output).expect("JSON report");
        assert_eq!(
            report["dependencies"][0]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(
            report["open_items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["code"] == "search-path-conflict")
        );
    }

    #[test]
    fn registered_attack_catalog_is_closed() {
        let catalog = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/attacks/scaffold/v1.toml"
        ));
        let expected = [
            "static-elf",
            "glibc-closure",
            "musl-closure",
            "missing-library",
            "conflicting-search-path",
            "plugin-load",
            "symlink-cycle",
            "identity-drift",
            "unsupported-dynamic-token",
        ];
        assert!(catalog.starts_with("schema = \"proofbound-runtime-scaffold-attacks/1\""));
        assert_eq!(catalog.matches("[[case]]").count(), expected.len());
        for id in expected {
            assert!(catalog.contains(&format!("id = \"{id}\"")));
        }
    }
}
