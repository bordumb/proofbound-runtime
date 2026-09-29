//! Proposed version 3 exact executable set and interpreter closure.

use std::path::{Path, PathBuf};

use proofbound_runtime_core::{ArtifactRole, AuthorityPath};

use crate::{Architecture, ResolutionError, ResolvedFile, RootedPathResolver};

const MAX_EXECUTABLES: usize = 64;
const SHEBANG_HEAD_BYTES: usize = 256;

/// One retained exact executable and any interpreter needed by the kernel.
#[derive(Debug)]
pub struct ExecutableSetMember {
    file: ResolvedFile,
    loader: Option<ResolvedFile>,
    script_interpreter: Option<PathBuf>,
}

impl ExecutableSetMember {
    #[must_use]
    pub const fn file(&self) -> &ResolvedFile {
        &self.file
    }

    #[must_use]
    pub const fn loader(&self) -> Option<&ResolvedFile> {
        self.loader.as_ref()
    }

    #[must_use]
    pub fn script_interpreter(&self) -> Option<&Path> {
        self.script_interpreter.as_deref()
    }

    pub fn revalidate_identities(&self) -> Result<(), ExecutableSetError> {
        self.file.revalidate_identity()?;
        if let Some(loader) = &self.loader {
            loader.revalidate_identity()?;
        }
        Ok(())
    }
}

/// Retains every declared executable and loader until launcher handoff.
#[derive(Debug)]
pub struct ExecutableSet {
    members: Vec<ExecutableSetMember>,
    command_index: usize,
}

impl ExecutableSet {
    #[must_use]
    pub fn members(&self) -> &[ExecutableSetMember] {
        &self.members
    }

    #[must_use]
    pub fn command(&self) -> &ExecutableSetMember {
        &self.members[self.command_index]
    }

    pub fn revalidate_identities(&self) -> Result<(), ExecutableSetError> {
        for member in &self.members {
            member.revalidate_identities()?;
        }
        Ok(())
    }
}

/// Fail-closed reason for a proposed executable set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableSetError {
    Count,
    Order,
    CommandNotMember,
    InterpreterNotMember,
    WritableMember,
    InvalidScript,
    Resolution(ResolutionError),
}

impl ExecutableSetError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Count => "plan.authority.execute.count",
            Self::Order => "plan.authority.execute.count",
            Self::CommandNotMember => "plan.authority.execute.command-not-member",
            Self::InterpreterNotMember => "plan.authority.execute.interpreter-not-member",
            Self::WritableMember => "plan.authority.execute.writable-member",
            Self::InvalidScript => "resolve.executable.script-invalid",
            Self::Resolution(error) => error.code(),
        }
    }
}

impl From<ResolutionError> for ExecutableSetError {
    fn from(error: ResolutionError) -> Self {
        Self::Resolution(error)
    }
}

impl RootedPathResolver {
    /// Resolve a normalized version 3 executable set and retain exact descriptors.
    ///
    /// `resolved_write_root` must be the canonical absolute path obtained from
    /// the retained write-root descriptor, not child-supplied path text.
    pub fn discover_executable_set(
        &self,
        members: &[AuthorityPath],
        command: &AuthorityPath,
        resolved_write_root: &Path,
        architecture: Architecture,
    ) -> Result<ExecutableSet, ExecutableSetError> {
        if members.is_empty() || members.len() > MAX_EXECUTABLES {
            return Err(ExecutableSetError::Count);
        }
        if !members.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(ExecutableSetError::Order);
        }
        let command_index = members
            .iter()
            .position(|member| member == command)
            .ok_or(ExecutableSetError::CommandNotMember)?;
        if !resolved_write_root.is_absolute()
            || resolved_write_root.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(ExecutableSetError::WritableMember);
        }

        let mut resolved = Vec::with_capacity(members.len());
        for path in members {
            let file = if Path::new(path.as_str()).is_absolute() {
                self.resolve_external_file(path, ArtifactRole::RuntimeExecutable)?
            } else {
                self.resolve_rooted_file(path, ArtifactRole::RuntimeExecutable)?
            };
            if file.identity().mode().get() & 0o111 == 0 {
                return Err(ExecutableSetError::Resolution(
                    ResolutionError::ExecutableModeMissing,
                ));
            }
            require_not_writable(self.resolved_root(), &file, resolved_write_root)?;
            let prefix = read_prefix(&file)?;
            let (loader, script_interpreter) = if prefix.starts_with(b"#!") {
                (None, Some(parse_shebang_interpreter(&prefix)?))
            } else {
                let closure = self.discover_executable(path, architecture)?;
                if closure.executable().identity() != file.identity()
                    || closure.executable().resolved_target() != file.resolved_target()
                {
                    return Err(ExecutableSetError::Resolution(
                        ResolutionError::IdentityDrift,
                    ));
                }
                let (discovered_file, loader) = closure.into_parts();
                drop(discovered_file);
                if let Some(loader) = &loader {
                    require_not_writable(self.resolved_root(), loader, resolved_write_root)?;
                }
                (loader, None)
            };
            resolved.push(ExecutableSetMember {
                file,
                loader,
                script_interpreter,
            });
        }
        for member in &resolved {
            if let Some(interpreter) = &member.script_interpreter
                && !members
                    .iter()
                    .any(|path| Path::new(path.as_str()) == interpreter)
            {
                return Err(ExecutableSetError::InterpreterNotMember);
            }
        }
        Ok(ExecutableSet {
            members: resolved,
            command_index,
        })
    }
}

fn require_not_writable(
    plan_root: &Path,
    file: &ResolvedFile,
    write_root: &Path,
) -> Result<(), ExecutableSetError> {
    let requested = if file.requested_path().is_absolute() {
        file.requested_path().to_path_buf()
    } else {
        plan_root.join(file.requested_path())
    };
    if path_below_write_root(&requested, write_root)
        || path_below_write_root(file.resolved_target(), write_root)
    {
        return Err(ExecutableSetError::WritableMember);
    }
    Ok(())
}

fn path_below_write_root(member: &Path, write_root: &Path) -> bool {
    member.starts_with(write_root)
}

fn parse_shebang_interpreter(head: &[u8]) -> Result<PathBuf, ExecutableSetError> {
    if !head.starts_with(b"#!") {
        return Err(ExecutableSetError::InvalidScript);
    }
    let newline = head
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or(ExecutableSetError::InvalidScript)?;
    let line = &head[2..newline];
    if line.len() > SHEBANG_HEAD_BYTES - 2 || line.contains(&b'\r') || line.contains(&0) {
        return Err(ExecutableSetError::InvalidScript);
    }
    let text = std::str::from_utf8(line).map_err(|_| ExecutableSetError::InvalidScript)?;
    let path = text
        .trim_start_matches([' ', '\t'])
        .split([' ', '\t'])
        .next()
        .ok_or(ExecutableSetError::InvalidScript)?;
    let path = PathBuf::from(path);
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(ExecutableSetError::InvalidScript);
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn read_prefix(file: &ResolvedFile) -> Result<Vec<u8>, ExecutableSetError> {
    use std::fs::File;
    use std::os::fd::BorrowedFd;
    use std::os::unix::fs::FileExt as _;

    let fd: BorrowedFd<'_> = file.as_fd();
    let source = File::from(
        fd.try_clone_to_owned()
            .map_err(|_| ExecutableSetError::Resolution(ResolutionError::IdentityUnavailable))?,
    );
    let mut bytes = vec![0; SHEBANG_HEAD_BYTES];
    let count = source
        .read_at(&mut bytes, 0)
        .map_err(|_| ExecutableSetError::Resolution(ResolutionError::IdentityUnavailable))?;
    bytes.truncate(count);
    file.revalidate_identity()?;
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_prefix(_file: &ResolvedFile) -> Result<Vec<u8>, ExecutableSetError> {
    Err(ExecutableSetError::Resolution(
        ResolutionError::UnsupportedOperatingSystem,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shebang_interpreter_must_be_exact_canonical_path() {
        assert_eq!(
            parse_shebang_interpreter(b"#!/usr/bin/python3 -I\nprint('x')").unwrap(),
            Path::new("/usr/bin/python3")
        );
        for head in [
            b"#!python3\n".as_slice(),
            b"#!/usr/bin/../bin/python3\n",
            b"#!/usr/bin/python3\r\n",
            b"#!/usr/bin/python3\0\n",
        ] {
            assert_eq!(
                parse_shebang_interpreter(head),
                Err(ExecutableSetError::InvalidScript)
            );
        }
    }

    #[test]
    fn writable_root_check_uses_path_components() {
        assert!(path_below_write_root(
            Path::new("/run/output/plugin"),
            Path::new("/run/output")
        ));
        assert!(!path_below_write_root(
            Path::new("/run/output-sibling/plugin"),
            Path::new("/run/output")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_set_retains_script_and_declared_interpreter() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "pbr-executable-set-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let script = root.join("plugin");
        std::fs::write(&script, b"#!/bin/true\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = root.join("output");
        std::fs::create_dir(&output).unwrap();
        let resolver = RootedPathResolver::open(&root).unwrap();
        let members = [
            AuthorityPath::new("/bin/true").unwrap(),
            AuthorityPath::new("plugin").unwrap(),
        ];
        let architecture = if cfg!(target_arch = "aarch64") {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        };
        let set = resolver
            .discover_executable_set(&members, &members[1], &output, architecture)
            .unwrap();
        assert_eq!(set.members().len(), 2);
        assert_eq!(
            set.command().script_interpreter(),
            Some(Path::new("/bin/true"))
        );
        set.revalidate_identities().unwrap();
        assert!(matches!(
            resolver.discover_executable_set(&members, &members[1], &root, architecture),
            Err(ExecutableSetError::WritableMember)
        ));
        assert!(matches!(
            resolver.discover_executable_set(&members[1..], &members[1], &output, architecture),
            Err(ExecutableSetError::InterpreterNotMember)
        ));
        std::fs::write(&script, b"#!/bin/true\n# substituted after resolution\n").unwrap();
        assert!(matches!(
            set.revalidate_identities(),
            Err(ExecutableSetError::Resolution(
                ResolutionError::IdentityDrift
            ))
        ));
        drop(set);
        drop(resolver);
        std::fs::remove_dir_all(root).unwrap();
    }
}
