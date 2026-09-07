//! Resolves registered files without reopening validated path names.

use core::fmt;
use std::path::{Component, Path, PathBuf};

use proofbound_runtime_core::{ArtifactIdentity, ArtifactRole, AuthorityPath};

use crate::Architecture;

const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER_SIZE: usize = 56;
const ELF_INTERPRETER_MAX: usize = 4_096;
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_MACHINE_AARCH64: u16 = 183;
const ELF_PROGRAM_INTERPRETER: u32 = 3;

/// Owns the descriptor for one resolved and identified regular file.
#[derive(Debug)]
pub struct ResolvedFile {
    requested_path: PathBuf,
    resolved_target: PathBuf,
    identity: ArtifactIdentity,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl ResolvedFile {
    /// Returns the exact path requested by the execution plan or ELF image.
    #[must_use]
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    /// Returns the target observed through the retained descriptor.
    #[must_use]
    pub fn resolved_target(&self) -> &Path {
        &self.resolved_target
    }

    /// Returns the identity computed from the retained descriptor.
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Recomputes identity from the retained descriptor immediately before use.
    pub fn revalidate_identity(&self) -> Result<(), ResolutionError> {
        #[cfg(target_os = "linux")]
        {
            let observed = identify_descriptor(&self.descriptor, self.identity.role())?;
            if observed != self.identity {
                return Err(ResolutionError::IdentityDrift);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ResolutionError::UnsupportedOperatingSystem)
        }
    }

    /// Borrows the retained descriptor for descriptor-relative launch.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }
}

/// Owns the exact executable and optional dynamic-loader descriptors.
#[derive(Debug)]
pub struct ExecutableClosure {
    executable: ResolvedFile,
    loader: Option<ResolvedFile>,
}

/// Revalidates one inherited executable descriptor against an expected identity.
pub fn revalidate_inherited_executable(
    descriptor: u32,
    expected: &ArtifactIdentity,
) -> Result<(), ResolutionError> {
    #[cfg(target_os = "linux")]
    {
        if descriptor > i32::MAX as u32 || expected.role() != ArtifactRole::RuntimeExecutable {
            return Err(ResolutionError::IdentityDrift);
        }
        let descriptor = crate::sys::duplicate_descriptor(descriptor as i32)
            .map_err(|_| ResolutionError::IdentityDrift)?;
        let observed = identify_descriptor(&descriptor, ArtifactRole::RuntimeExecutable)?;
        if &observed == expected {
            Ok(())
        } else {
            Err(ResolutionError::IdentityDrift)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (descriptor, expected);
        Err(ResolutionError::UnsupportedOperatingSystem)
    }
}

impl ExecutableClosure {
    /// Returns the identified executable.
    #[must_use]
    pub const fn executable(&self) -> &ResolvedFile {
        &self.executable
    }

    /// Returns the identified ELF interpreter, if the executable is dynamic.
    #[must_use]
    pub const fn loader(&self) -> Option<&ResolvedFile> {
        self.loader.as_ref()
    }

    /// Revalidates every descriptor immediately before launcher handoff.
    pub fn revalidate_identities(&self) -> Result<(), ResolutionError> {
        self.executable.revalidate_identity()?;
        if let Some(loader) = &self.loader {
            loader.revalidate_identity()?;
        }
        Ok(())
    }
}

/// Owns the registered plan-root descriptor used for confined resolution.
#[derive(Debug)]
pub struct RootedPathResolver {
    requested_root: PathBuf,
    resolved_root: PathBuf,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl RootedPathResolver {
    /// Opens and retains a non-symlink directory as the plan root.
    pub fn open(root: &Path) -> Result<Self, ResolutionError> {
        #[cfg(target_os = "linux")]
        {
            let descriptor =
                crate::sys::open_directory(root).map_err(|_| ResolutionError::RootUnavailable)?;
            let resolved_root = descriptor_target(&descriptor)?;
            Ok(Self {
                requested_root: root.to_path_buf(),
                resolved_root,
                descriptor,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            Err(ResolutionError::UnsupportedOperatingSystem)
        }
    }

    /// Returns the path used to open the plan root.
    #[must_use]
    pub fn requested_root(&self) -> &Path {
        &self.requested_root
    }

    /// Returns the target observed through the retained root descriptor.
    #[must_use]
    pub fn resolved_root(&self) -> &Path {
        &self.resolved_root
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn root_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }

    /// Resolves a relative file beneath the retained plan root.
    pub fn resolve_rooted_file(
        &self,
        requested: &AuthorityPath,
        role: ArtifactRole,
    ) -> Result<ResolvedFile, ResolutionError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            let path = Path::new(requested.as_str());
            require_confined_relative_path(path)?;
            let descriptor = crate::sys::openat2_file(
                self.descriptor.as_raw_fd(),
                path,
                crate::sys::RESOLVE_BENEATH | crate::sys::RESOLVE_NO_MAGICLINKS,
            )
            .map_err(map_open_error)?;
            finish_resolution(path, role, descriptor)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (requested, role);
            Err(ResolutionError::UnsupportedOperatingSystem)
        }
    }

    /// Resolves an absolute file with an explicitly external executable role.
    pub fn resolve_external_file(
        &self,
        requested: &AuthorityPath,
        role: ArtifactRole,
    ) -> Result<ResolvedFile, ResolutionError> {
        #[cfg(target_os = "linux")]
        {
            let path = Path::new(requested.as_str());
            require_external_role(role)?;
            require_canonical_absolute_path(path)?;
            let descriptor =
                crate::sys::openat2_file(libc::AT_FDCWD, path, crate::sys::RESOLVE_NO_MAGICLINKS)
                    .map_err(map_open_error)?;
            finish_resolution(path, role, descriptor)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (requested, role);
            Err(ResolutionError::UnsupportedOperatingSystem)
        }
    }

    /// Resolves and verifies the exact executable and ELF interpreter closure.
    pub fn resolve_executable(
        &self,
        requested: &AuthorityPath,
        expected_executable: &ArtifactIdentity,
        expected_loader: Option<&ArtifactIdentity>,
        architecture: Architecture,
    ) -> Result<ExecutableClosure, ResolutionError> {
        require_role(expected_executable, ArtifactRole::RuntimeExecutable)?;
        if let Some(loader) = expected_loader {
            require_role(loader, ArtifactRole::RuntimeLoaderExecutable)?;
        }

        let closure = self.discover_executable(requested, architecture)?;
        require_identity(&closure.executable, expected_executable)?;
        match (&closure.loader, expected_loader) {
            (Some(loader), Some(expected)) => require_identity(loader, expected)?,
            (Some(_), None) => return Err(ResolutionError::LoaderIdentityMissing),
            (None, Some(_)) => return Err(ResolutionError::LoaderIdentityUnexpected),
            (None, None) => {}
        }
        Ok(closure)
    }

    /// Resolves and identifies an executable and its exact ELF interpreter.
    ///
    /// The returned descriptors retain the observed files. The caller must
    /// bind both identities into the execution receipt and revalidate them
    /// immediately before launcher handoff.
    pub fn discover_executable(
        &self,
        requested: &AuthorityPath,
        architecture: Architecture,
    ) -> Result<ExecutableClosure, ResolutionError> {
        let executable = if Path::new(requested.as_str()).is_absolute() {
            self.resolve_external_file(requested, ArtifactRole::RuntimeExecutable)?
        } else {
            self.resolve_rooted_file(requested, ArtifactRole::RuntimeExecutable)?
        };
        require_executable_mode(&executable)?;

        let loader = read_elf_interpreter(&executable, architecture)?
            .map(|path| {
                let path = path
                    .to_str()
                    .ok_or(ResolutionError::ElfInterpreterInvalid)?;
                let path = AuthorityPath::new(path.to_owned())
                    .map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
                let loader =
                    self.resolve_external_file(&path, ArtifactRole::RuntimeLoaderExecutable)?;
                require_executable_mode(&loader)?;
                Ok(loader)
            })
            .transpose()?;

        Ok(ExecutableClosure { executable, loader })
    }
}

/// Identifies one fail-closed resolution result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The registered plan root could not be opened as a non-symlink directory.
    RootUnavailable,
    /// A rooted path was absolute or contained a parent component.
    PathEscapesRoot,
    /// An external path was not absolute and lexically normalized.
    ExternalPathInvalid,
    /// The supplied role does not authorize external resolution.
    ExternalRoleInvalid,
    /// The kernel cannot provide the required `openat2` resolution guarantee.
    Openat2Unavailable,
    /// The requested path could not be opened.
    PathUnavailable,
    /// Resolution encountered a symlink loop or forbidden magic link.
    SymlinkInvalid,
    /// The resolved object was not a regular file.
    ForbiddenFileKind,
    /// The resolved executable did not have an execute permission bit.
    ExecutableModeMissing,
    /// A registered identity had the wrong artifact role.
    ArtifactRoleMismatch,
    /// The observed descriptor identity did not match the registered identity.
    IdentityMismatch,
    /// A retained descriptor changed identity before use.
    IdentityDrift,
    /// File identity could not be measured consistently.
    IdentityUnavailable,
    /// The executable was not a valid 64-bit little-endian ELF image.
    ElfMalformed,
    /// The ELF machine did not match the selected platform architecture.
    ElfArchitectureMismatch,
    /// The ELF interpreter segment was malformed or noncanonical.
    ElfInterpreterInvalid,
    /// A dynamic executable had no registered loader identity.
    LoaderIdentityMissing,
    /// A static executable had an unexpected loader identity.
    LoaderIdentityUnexpected,
}

impl ResolutionError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "resolve.os.unsupported",
            Self::RootUnavailable => "resolve.root.unavailable",
            Self::PathEscapesRoot => "resolve.path.escapes-root",
            Self::ExternalPathInvalid => "resolve.path.external-invalid",
            Self::ExternalRoleInvalid => "resolve.role.external-invalid",
            Self::Openat2Unavailable => "resolve.openat2.unavailable",
            Self::PathUnavailable => "resolve.path.unavailable",
            Self::SymlinkInvalid => "resolve.path.symlink-invalid",
            Self::ForbiddenFileKind => "resolve.file-kind.forbidden",
            Self::ExecutableModeMissing => "resolve.executable.mode-missing",
            Self::ArtifactRoleMismatch => "resolve.identity.role-mismatch",
            Self::IdentityMismatch => "resolve.identity.mismatch",
            Self::IdentityDrift => "resolve.identity.drift",
            Self::IdentityUnavailable => "resolve.identity.unavailable",
            Self::ElfMalformed => "resolve.elf.malformed",
            Self::ElfArchitectureMismatch => "resolve.elf.architecture-mismatch",
            Self::ElfInterpreterInvalid => "resolve.elf.interpreter-invalid",
            Self::LoaderIdentityMissing => "resolve.loader.identity-missing",
            Self::LoaderIdentityUnexpected => "resolve.loader.identity-unexpected",
        }
    }
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ResolutionError {}

/// Parses the optional `PT_INTERP` path from a complete ELF image.
pub fn parse_elf_interpreter(
    image: &[u8],
    architecture: Architecture,
) -> Result<Option<PathBuf>, ResolutionError> {
    let layout = parse_elf_layout(
        image
            .get(..ELF_HEADER_SIZE)
            .ok_or(ResolutionError::ElfMalformed)?,
        architecture,
    )?;
    let table_size = usize::from(layout.entry_size)
        .checked_mul(usize::from(layout.entry_count))
        .ok_or(ResolutionError::ElfMalformed)?;
    let table_start =
        usize::try_from(layout.table_offset).map_err(|_| ResolutionError::ElfMalformed)?;
    let table_end = table_start
        .checked_add(table_size)
        .ok_or(ResolutionError::ElfMalformed)?;
    let table = image
        .get(table_start..table_end)
        .ok_or(ResolutionError::ElfMalformed)?;
    let segment = interpreter_segment(table, layout.entry_size, layout.entry_count)?;
    let Some((offset, size)) = segment else {
        return Ok(None);
    };
    let start = usize::try_from(offset).map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
    let size = usize::try_from(size).map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
    let end = start
        .checked_add(size)
        .ok_or(ResolutionError::ElfInterpreterInvalid)?;
    parse_interpreter_bytes(
        image
            .get(start..end)
            .ok_or(ResolutionError::ElfInterpreterInvalid)?,
    )
    .map(Some)
}

#[derive(Clone, Copy)]
struct ElfLayout {
    table_offset: u64,
    entry_size: u16,
    entry_count: u16,
}

fn parse_elf_layout(
    header: &[u8],
    architecture: Architecture,
) -> Result<ElfLayout, ResolutionError> {
    if header.len() != ELF_HEADER_SIZE
        || header.get(..4) != Some(b"\x7fELF")
        || header[4] != ELF_CLASS_64
        || header[5] != ELF_DATA_LITTLE_ENDIAN
        || header[6] != 1
        || read_u16(header, 52)? != ELF_HEADER_SIZE as u16
    {
        return Err(ResolutionError::ElfMalformed);
    }
    let expected_machine = match architecture {
        Architecture::X86_64 => ELF_MACHINE_X86_64,
        Architecture::Aarch64 => ELF_MACHINE_AARCH64,
    };
    if read_u16(header, 18)? != expected_machine {
        return Err(ResolutionError::ElfArchitectureMismatch);
    }
    let entry_size = read_u16(header, 54)?;
    if usize::from(entry_size) < ELF_PROGRAM_HEADER_SIZE {
        return Err(ResolutionError::ElfMalformed);
    }
    Ok(ElfLayout {
        table_offset: read_u64(header, 32)?,
        entry_size,
        entry_count: read_u16(header, 56)?,
    })
}

fn interpreter_segment(
    table: &[u8],
    entry_size: u16,
    entry_count: u16,
) -> Result<Option<(u64, u64)>, ResolutionError> {
    let entry_size = usize::from(entry_size);
    let mut interpreter = None;
    for index in 0..usize::from(entry_count) {
        let start = index
            .checked_mul(entry_size)
            .ok_or(ResolutionError::ElfMalformed)?;
        let entry = table
            .get(start..start + ELF_PROGRAM_HEADER_SIZE)
            .ok_or(ResolutionError::ElfMalformed)?;
        if read_u32(entry, 0)? == ELF_PROGRAM_INTERPRETER {
            if interpreter.is_some() {
                return Err(ResolutionError::ElfInterpreterInvalid);
            }
            let offset = read_u64(entry, 8)?;
            let size = read_u64(entry, 32)?;
            if !(2..=ELF_INTERPRETER_MAX as u64).contains(&size) {
                return Err(ResolutionError::ElfInterpreterInvalid);
            }
            interpreter = Some((offset, size));
        }
    }
    Ok(interpreter)
}

fn parse_interpreter_bytes(bytes: &[u8]) -> Result<PathBuf, ResolutionError> {
    let Some((&0, path)) = bytes.split_last() else {
        return Err(ResolutionError::ElfInterpreterInvalid);
    };
    if path.is_empty() || path.contains(&0) {
        return Err(ResolutionError::ElfInterpreterInvalid);
    }
    let text = core::str::from_utf8(path).map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
    let path = PathBuf::from(text);
    require_canonical_absolute_path(&path).map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
    Ok(path)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ResolutionError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ResolutionError::ElfMalformed)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ResolutionError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ResolutionError::ElfMalformed)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ResolutionError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ResolutionError::ElfMalformed)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

#[cfg(target_os = "linux")]
fn require_confined_relative_path(path: &Path) -> Result<(), ResolutionError> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        Err(ResolutionError::PathEscapesRoot)
    } else {
        Ok(())
    }
}

fn require_canonical_absolute_path(path: &Path) -> Result<(), ResolutionError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Err(ResolutionError::ExternalPathInvalid)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn require_external_role(role: ArtifactRole) -> Result<(), ResolutionError> {
    if matches!(
        role,
        ArtifactRole::RuntimeExecutable
            | ArtifactRole::RuntimeLoaderExecutable
            | ArtifactRole::RuntimeLibrary
    ) {
        Ok(())
    } else {
        Err(ResolutionError::ExternalRoleInvalid)
    }
}

fn require_role(identity: &ArtifactIdentity, role: ArtifactRole) -> Result<(), ResolutionError> {
    if identity.role() == role {
        Ok(())
    } else {
        Err(ResolutionError::ArtifactRoleMismatch)
    }
}

fn require_identity(
    file: &ResolvedFile,
    expected: &ArtifactIdentity,
) -> Result<(), ResolutionError> {
    if file.identity() == expected {
        Ok(())
    } else {
        Err(ResolutionError::IdentityMismatch)
    }
}

fn require_executable_mode(file: &ResolvedFile) -> Result<(), ResolutionError> {
    if file.identity.mode().get() & 0o111 == 0 {
        Err(ResolutionError::ExecutableModeMissing)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn finish_resolution(
    requested: &Path,
    role: ArtifactRole,
    descriptor: std::os::fd::OwnedFd,
) -> Result<ResolvedFile, ResolutionError> {
    let resolved_target = descriptor_target(&descriptor)?;
    let identity = identify_descriptor(&descriptor, role)?;
    Ok(ResolvedFile {
        requested_path: requested.to_path_buf(),
        resolved_target,
        identity,
        descriptor,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn descriptor_target(
    descriptor: &std::os::fd::OwnedFd,
) -> Result<PathBuf, ResolutionError> {
    use std::os::fd::AsRawFd as _;

    std::fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
        .map_err(|_| ResolutionError::IdentityUnavailable)
}

#[cfg(target_os = "linux")]
pub(crate) fn identify_descriptor(
    descriptor: &std::os::fd::OwnedFd,
    role: ArtifactRole,
) -> Result<ArtifactIdentity, ResolutionError> {
    use std::fs::File;
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

    use proofbound_runtime_core::{FileMode, Sha256Digest};
    use sha2::{Digest as _, Sha256};

    let file = File::from(
        descriptor
            .try_clone()
            .map_err(|_| ResolutionError::IdentityUnavailable)?,
    );
    let before = file
        .metadata()
        .map_err(|_| ResolutionError::IdentityUnavailable)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(ResolutionError::ForbiddenFileKind);
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut offset = 0_u64;
    loop {
        let read = file
            .read_at(&mut buffer, offset)
            .map_err(|_| ResolutionError::IdentityUnavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).expect("buffer length fits u64"))
            .ok_or(ResolutionError::IdentityUnavailable)?;
    }
    let after = file
        .metadata()
        .map_err(|_| ResolutionError::IdentityUnavailable)?;
    if metadata_changed(&before, &after) || offset != after.len() {
        return Err(ResolutionError::IdentityDrift);
    }
    let mode =
        u16::try_from(after.mode() & 0o7777).map_err(|_| ResolutionError::IdentityUnavailable)?;
    let mode = FileMode::new(mode).map_err(|_| ResolutionError::IdentityUnavailable)?;
    Ok(ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes(hasher.finalize().into()),
        after.len(),
        mode,
    ))
}

#[cfg(target_os = "linux")]
fn metadata_changed(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}

#[cfg(target_os = "linux")]
fn read_elf_interpreter(
    file: &ResolvedFile,
    architecture: Architecture,
) -> Result<Option<PathBuf>, ResolutionError> {
    use std::fs::File;
    use std::os::unix::fs::FileExt as _;

    let source = File::from(
        file.descriptor
            .try_clone()
            .map_err(|_| ResolutionError::IdentityUnavailable)?,
    );
    let mut header = [0_u8; ELF_HEADER_SIZE];
    source
        .read_exact_at(&mut header, 0)
        .map_err(|_| ResolutionError::ElfMalformed)?;
    let layout = parse_elf_layout(&header, architecture)?;
    let table_size = usize::from(layout.entry_size)
        .checked_mul(usize::from(layout.entry_count))
        .filter(|size| *size <= 1024 * 1024)
        .ok_or(ResolutionError::ElfMalformed)?;
    let mut table = vec![0_u8; table_size];
    source
        .read_exact_at(&mut table, layout.table_offset)
        .map_err(|_| ResolutionError::ElfMalformed)?;
    let Some((offset, size)) = interpreter_segment(&table, layout.entry_size, layout.entry_count)?
    else {
        return Ok(None);
    };
    let size = usize::try_from(size).map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
    let mut bytes = vec![0_u8; size];
    source
        .read_exact_at(&mut bytes, offset)
        .map_err(|_| ResolutionError::ElfInterpreterInvalid)?;
    parse_interpreter_bytes(&bytes).map(Some)
}

#[cfg(not(target_os = "linux"))]
fn read_elf_interpreter(
    _file: &ResolvedFile,
    _architecture: Architecture,
) -> Result<Option<PathBuf>, ResolutionError> {
    Err(ResolutionError::UnsupportedOperatingSystem)
}

#[cfg(target_os = "linux")]
pub(crate) fn map_open_error(error: std::io::Error) -> ResolutionError {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => ResolutionError::Openat2Unavailable,
        Some(libc::EXDEV) => ResolutionError::PathEscapesRoot,
        Some(libc::ELOOP) => ResolutionError::SymlinkInvalid,
        _ => ResolutionError::PathUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/authority/path-resolution-v1.toml"
    ));

    fn elf(machine: u16, interpreter: Option<&[u8]>) -> Vec<u8> {
        let count = u16::from(interpreter.is_some());
        let mut image = vec![0_u8; ELF_HEADER_SIZE + usize::from(count) * ELF_PROGRAM_HEADER_SIZE];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = ELF_CLASS_64;
        image[5] = ELF_DATA_LITTLE_ENDIAN;
        image[6] = 1;
        image[18..20].copy_from_slice(&machine.to_le_bytes());
        image[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        image[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        image[54..56].copy_from_slice(&(ELF_PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        image[56..58].copy_from_slice(&count.to_le_bytes());
        if let Some(interpreter) = interpreter {
            let offset = image.len() as u64;
            image[ELF_HEADER_SIZE..ELF_HEADER_SIZE + 4]
                .copy_from_slice(&ELF_PROGRAM_INTERPRETER.to_le_bytes());
            image[ELF_HEADER_SIZE + 8..ELF_HEADER_SIZE + 16].copy_from_slice(&offset.to_le_bytes());
            image[ELF_HEADER_SIZE + 32..ELF_HEADER_SIZE + 40]
                .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
            image.extend_from_slice(interpreter);
        }
        image
    }

    #[test]
    fn parses_static_and_dynamic_elf_images() {
        let static_image = elf(ELF_MACHINE_X86_64, None);
        assert_eq!(
            parse_elf_interpreter(&static_image, Architecture::X86_64),
            Ok(None)
        );

        let dynamic = elf(ELF_MACHINE_X86_64, Some(b"/lib64/ld-linux.so.2\0"));
        assert_eq!(
            parse_elf_interpreter(&dynamic, Architecture::X86_64),
            Ok(Some(PathBuf::from("/lib64/ld-linux.so.2")))
        );
    }

    #[test]
    fn rejects_wrong_architecture_and_malformed_interpreters() {
        let image = elf(ELF_MACHINE_AARCH64, None);
        assert_eq!(
            parse_elf_interpreter(&image, Architecture::X86_64),
            Err(ResolutionError::ElfArchitectureMismatch)
        );

        for interpreter in [
            b"relative-loader\0".as_slice(),
            b"/lib/../loader\0".as_slice(),
            b"/loader".as_slice(),
            b"/bad\0tail\0".as_slice(),
        ] {
            let image = elf(ELF_MACHINE_X86_64, Some(interpreter));
            assert_eq!(
                parse_elf_interpreter(&image, Architecture::X86_64),
                Err(ResolutionError::ElfInterpreterInvalid)
            );
        }
    }

    #[test]
    fn rejects_duplicate_interpreter_segments() {
        let mut image = elf(ELF_MACHINE_X86_64, Some(b"/loader\0"));
        image[56..58].copy_from_slice(&2_u16.to_le_bytes());
        let first_end = ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE;
        image.splice(first_end..first_end, vec![0_u8; ELF_PROGRAM_HEADER_SIZE]);
        image[first_end..first_end + 4].copy_from_slice(&ELF_PROGRAM_INTERPRETER.to_le_bytes());
        image[first_end + 8..first_end + 16].copy_from_slice(&128_u64.to_le_bytes());
        image[first_end + 32..first_end + 40].copy_from_slice(&8_u64.to_le_bytes());
        assert_eq!(
            parse_elf_interpreter(&image, Architecture::X86_64),
            Err(ResolutionError::ElfInterpreterInvalid)
        );
    }

    #[test]
    fn error_codes_are_unique_and_stable() {
        let errors = [
            ResolutionError::UnsupportedOperatingSystem,
            ResolutionError::RootUnavailable,
            ResolutionError::PathEscapesRoot,
            ResolutionError::ExternalPathInvalid,
            ResolutionError::ExternalRoleInvalid,
            ResolutionError::Openat2Unavailable,
            ResolutionError::PathUnavailable,
            ResolutionError::SymlinkInvalid,
            ResolutionError::ForbiddenFileKind,
            ResolutionError::ExecutableModeMissing,
            ResolutionError::ArtifactRoleMismatch,
            ResolutionError::IdentityMismatch,
            ResolutionError::IdentityDrift,
            ResolutionError::IdentityUnavailable,
            ResolutionError::ElfMalformed,
            ResolutionError::ElfArchitectureMismatch,
            ResolutionError::ElfInterpreterInvalid,
            ResolutionError::LoaderIdentityMissing,
            ResolutionError::LoaderIdentityUnexpected,
        ];
        let mut codes = errors.map(ResolutionError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn frozen_path_resolution_attack_catalog_is_closed() {
        let expected_ids = [
            "parent-traversal",
            "absolute-rooted-path",
            "external-role-amplification",
            "relative-external-path",
            "magic-link-substitution",
            "executable-identity-substitution",
            "loader-identity-omission",
            "loader-identity-substitution",
            "post-resolution-mutation",
            "read-directory-symlink",
            "read-directory-inventory-drift",
        ];
        assert!(
            ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-path-resolution-attacks/1\"")
        );
        assert_eq!(
            ATTACK_CATALOG.matches("[[attack]]").count(),
            expected_ids.len()
        );
        for id in expected_ids {
            assert!(
                ATTACK_CATALOG.contains(&format!("id = \"{id}\"")),
                "missing registered path-resolution attack {id}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::sync::atomic::{AtomicU64, Ordering};

        use proofbound_runtime_core::ArtifactRole;

        use super::*;

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "proofbound-runtime-{label}-{}-{sequence}",
                    std::process::id()
                ));
                fs::create_dir(&path).expect("create isolated test directory");
                Self(path)
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).expect("remove isolated test directory");
            }
        }

        #[test]
        fn rooted_resolution_retains_descriptor_and_detects_drift() {
            let root = TestDirectory::new("identity-drift");
            let executable = root.0.join("tool");
            fs::write(&executable, b"registered bytes").expect("write test executable");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
                .expect("set executable mode");

            let resolver = RootedPathResolver::open(&root.0).expect("open plan root");
            let requested = AuthorityPath::new("tool").expect("valid relative path");
            let resolved = resolver
                .resolve_rooted_file(&requested, ArtifactRole::RuntimeExecutable)
                .expect("resolve registered executable");
            assert_eq!(resolved.identity().size(), 16);
            assert_eq!(resolved.identity().mode().get(), 0o755);
            resolved
                .revalidate_identity()
                .expect("identity remains exact");

            fs::write(&executable, b"substituted bytes").expect("mutate test executable");
            assert_eq!(
                resolved.revalidate_identity(),
                Err(ResolutionError::IdentityDrift)
            );
        }

        #[test]
        fn rooted_resolution_rejects_traversal_and_symlink_escape() {
            let root = TestDirectory::new("path-root");
            let outside = TestDirectory::new("path-outside");
            fs::write(outside.0.join("secret"), b"secret").expect("write outside file");
            symlink(&outside.0, root.0.join("escape")).expect("create escape symlink");
            let resolver = RootedPathResolver::open(&root.0).expect("open plan root");

            let traversal = AuthorityPath::new("../secret").expect("valid authority text");
            assert!(matches!(
                resolver.resolve_rooted_file(&traversal, ArtifactRole::ProjectInput),
                Err(ResolutionError::PathEscapesRoot)
            ));
            let escape = AuthorityPath::new("escape/secret").expect("valid authority text");
            assert!(matches!(
                resolver.resolve_rooted_file(&escape, ArtifactRole::ProjectInput),
                Err(ResolutionError::PathEscapesRoot)
            ));
        }

        #[test]
        fn external_resolution_requires_a_typed_executable_role() {
            let root = TestDirectory::new("external-role");
            let resolver = RootedPathResolver::open(&root.0).expect("open plan root");
            let path = AuthorityPath::new("/etc/passwd").expect("valid absolute path");
            assert!(matches!(
                resolver.resolve_external_file(&path, ArtifactRole::ProjectInput),
                Err(ResolutionError::ExternalRoleInvalid)
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_resolution_is_never_positive_evidence() {
        assert!(matches!(
            RootedPathResolver::open(Path::new(".")),
            Err(ResolutionError::UnsupportedOperatingSystem)
        ));
    }
}
