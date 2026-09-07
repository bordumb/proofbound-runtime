//! Resolves directory authority and binds deterministic directory inventories.

use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::path::Component;

use proofbound_runtime_core::{ArtifactIdentity, ArtifactRole, AuthorityPath};

use crate::{ResolutionError, ResolvedFile, RootedPathResolver};

#[cfg(target_os = "linux")]
const DIRECTORY_IDENTITY_DOMAIN: &[u8] = b"proofbound-runtime-directory-inventory/1\n";

/// Owns one resolved directory and its deterministic inventory identity.
#[derive(Debug)]
pub struct ResolvedDirectory {
    requested_path: PathBuf,
    resolved_target: PathBuf,
    identity: ArtifactIdentity,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl ResolvedDirectory {
    /// Returns the exact path supplied by the execution plan.
    #[must_use]
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    /// Returns the target observed through the retained descriptor.
    #[must_use]
    pub fn resolved_target(&self) -> &Path {
        &self.resolved_target
    }

    /// Returns the domain-separated directory inventory identity.
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Recomputes the inventory and rejects any changed entry or metadata.
    pub fn revalidate_identity(&self) -> Result<(), ResolutionError> {
        #[cfg(target_os = "linux")]
        {
            let observed = identify_directory(&self.descriptor, self.identity.role())?;
            if observed == self.identity {
                Ok(())
            } else {
                Err(ResolutionError::IdentityDrift)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(ResolutionError::UnsupportedOperatingSystem)
        }
    }

    /// Borrows the retained descriptor for launcher handoff.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }
}

/// Owns one registered readable file or directory.
#[derive(Debug)]
pub enum ResolvedReadPath {
    /// A regular file with an exact byte identity.
    File(ResolvedFile),
    /// A directory with a domain-separated recursive inventory identity.
    Directory(ResolvedDirectory),
}

impl ResolvedReadPath {
    /// Returns the identity bound into the receipt input set.
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        match self {
            Self::File(file) => file.identity(),
            Self::Directory(directory) => directory.identity(),
        }
    }

    /// Revalidates the retained file or complete directory inventory.
    pub fn revalidate_identity(&self) -> Result<(), ResolutionError> {
        match self {
            Self::File(file) => file.revalidate_identity(),
            Self::Directory(directory) => directory.revalidate_identity(),
        }
    }

    /// Borrows the retained descriptor for a Landlock read rule.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match self {
            Self::File(file) => file.as_fd(),
            Self::Directory(directory) => directory.as_fd(),
        }
    }
}

impl RootedPathResolver {
    /// Resolves the registered working directory beneath the plan root.
    pub fn resolve_working_directory(
        &self,
        requested: &AuthorityPath,
    ) -> Result<ResolvedDirectory, ResolutionError> {
        resolve_rooted_directory(self, requested, ArtifactRole::WorkingDirectory)
    }

    /// Resolves one registered project input or external runtime-library root.
    pub fn resolve_read_path(
        &self,
        requested: &AuthorityPath,
        role: ArtifactRole,
    ) -> Result<ResolvedReadPath, ResolutionError> {
        if !matches!(
            role,
            ArtifactRole::ProjectInput | ArtifactRole::RuntimeLibrary
        ) {
            return Err(ResolutionError::ArtifactRoleMismatch);
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            let path = Path::new(requested.as_str());
            let (parent, resolution) = if role == ArtifactRole::ProjectInput {
                require_rooted(path)?;
                (self.root_fd().as_raw_fd(), crate::sys::RESOLVE_BENEATH)
            } else {
                require_external(path)?;
                (libc::AT_FDCWD, 0)
            };
            let resolution =
                resolution | crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS;
            let inspected = crate::sys::openat2_path(parent, path, resolution)
                .map_err(crate::resolve::map_open_error)?;
            let metadata = std::fs::File::from(
                inspected
                    .try_clone()
                    .map_err(|_| ResolutionError::IdentityUnavailable)?,
            )
            .metadata()
            .map_err(|_| ResolutionError::IdentityUnavailable)?;
            if metadata.file_type().is_symlink() {
                Err(ResolutionError::SymlinkInvalid)
            } else if metadata.is_file() {
                let file = if role == ArtifactRole::ProjectInput {
                    self.resolve_rooted_file(requested, role)?
                } else {
                    self.resolve_external_file(requested, role)?
                };
                Ok(ResolvedReadPath::File(file))
            } else if metadata.is_dir() {
                let descriptor = crate::sys::openat2_directory(parent, path, resolution)
                    .map_err(crate::resolve::map_open_error)?;
                Ok(ResolvedReadPath::Directory(finish_directory(
                    path, role, descriptor,
                )?))
            } else {
                Err(ResolutionError::ForbiddenFileKind)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = requested;
            Err(ResolutionError::UnsupportedOperatingSystem)
        }
    }
}

fn resolve_rooted_directory(
    resolver: &RootedPathResolver,
    requested: &AuthorityPath,
    role: ArtifactRole,
) -> Result<ResolvedDirectory, ResolutionError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;

        let path = Path::new(requested.as_str());
        require_rooted(path)?;
        let descriptor = crate::sys::openat2_directory(
            resolver.root_fd().as_raw_fd(),
            path,
            crate::sys::RESOLVE_BENEATH
                | crate::sys::RESOLVE_NO_MAGICLINKS
                | crate::sys::RESOLVE_NO_SYMLINKS,
        )
        .map_err(crate::resolve::map_open_error)?;
        finish_directory(path, role, descriptor)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (resolver, requested, role);
        Err(ResolutionError::UnsupportedOperatingSystem)
    }
}

#[cfg(target_os = "linux")]
fn finish_directory(
    requested: &Path,
    role: ArtifactRole,
    descriptor: std::os::fd::OwnedFd,
) -> Result<ResolvedDirectory, ResolutionError> {
    let resolved_target = crate::resolve::descriptor_target(&descriptor)?;
    let identity = identify_directory(&descriptor, role)?;
    Ok(ResolvedDirectory {
        requested_path: requested.to_path_buf(),
        resolved_target,
        identity,
        descriptor,
    })
}

#[cfg(target_os = "linux")]
fn identify_directory(
    descriptor: &std::os::fd::OwnedFd,
    role: ArtifactRole,
) -> Result<ArtifactIdentity, ResolutionError> {
    use std::os::unix::fs::MetadataExt as _;

    use proofbound_runtime_core::{FileMode, Sha256Digest};
    use sha2::{Digest as _, Sha256};

    let before = directory_metadata(descriptor)?;
    let mut entries = Vec::new();
    inventory_directory(descriptor, Path::new(""), &mut entries)?;
    let after = directory_metadata(descriptor)?;
    if directory_metadata_changed(&before, &after) {
        return Err(ResolutionError::IdentityDrift);
    }
    entries.sort_by(|left, right| path_bytes(&left.0).cmp(path_bytes(&right.0)));

    let mut hasher = Sha256::new();
    hasher.update(DIRECTORY_IDENTITY_DOMAIN);
    hasher.update(role.as_str().as_bytes());
    let mut encoded_size = u64::try_from(DIRECTORY_IDENTITY_DOMAIN.len() + role.as_str().len())
        .map_err(|_| ResolutionError::IdentityUnavailable)?;
    for (path, identity) in entries {
        let bytes = path_bytes(&path);
        let path_length =
            u64::try_from(bytes.len()).map_err(|_| ResolutionError::IdentityUnavailable)?;
        hasher.update(path_length.to_be_bytes());
        hasher.update(bytes);
        hasher.update(identity.digest().as_bytes());
        hasher.update(identity.size().to_be_bytes());
        hasher.update(identity.mode().get().to_be_bytes());
        encoded_size = encoded_size
            .checked_add(8 + path_length + 32 + 8 + 2)
            .ok_or(ResolutionError::IdentityUnavailable)?;
    }
    let mode =
        u16::try_from(after.mode() & 0o7777).map_err(|_| ResolutionError::IdentityUnavailable)?;
    Ok(ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes(hasher.finalize().into()),
        encoded_size,
        FileMode::new(mode).map_err(|_| ResolutionError::IdentityUnavailable)?,
    ))
}

#[cfg(target_os = "linux")]
fn inventory_directory(
    descriptor: &std::os::fd::OwnedFd,
    relative_parent: &Path,
    entries: &mut Vec<(PathBuf, ArtifactIdentity)>,
) -> Result<(), ResolutionError> {
    use std::os::fd::AsRawFd as _;

    let before = directory_metadata(descriptor)?;
    for name in directory_names(descriptor)? {
        let path = Path::new(&name);
        let relative_path = relative_parent.join(path);
        let inspected = crate::sys::openat2_path(
            descriptor.as_raw_fd(),
            path,
            crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
        )
        .map_err(crate::resolve::map_open_error)?;
        let metadata = std::fs::File::from(
            inspected
                .try_clone()
                .map_err(|_| ResolutionError::IdentityUnavailable)?,
        )
        .metadata()
        .map_err(|_| ResolutionError::IdentityUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(ResolutionError::SymlinkInvalid);
        } else if metadata.is_dir() {
            let directory = crate::sys::openat2_directory(
                descriptor.as_raw_fd(),
                path,
                crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
            )
            .map_err(crate::resolve::map_open_error)?;
            inventory_directory(&directory, &relative_path, entries)?;
        } else if metadata.is_file() {
            let file = crate::sys::openat2_file(
                descriptor.as_raw_fd(),
                path,
                crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
            )
            .map_err(crate::resolve::map_open_error)?;
            let identity = crate::resolve::identify_descriptor(&file, ArtifactRole::ProjectInput)?;
            entries.push((relative_path, identity));
        } else {
            return Err(ResolutionError::ForbiddenFileKind);
        }
    }
    let after = directory_metadata(descriptor)?;
    if directory_metadata_changed(&before, &after) {
        Err(ResolutionError::IdentityDrift)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn directory_names(
    descriptor: &std::os::fd::OwnedFd,
) -> Result<Vec<std::ffi::OsString>, ResolutionError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let mut names = std::fs::read_dir(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
        .map_err(|_| ResolutionError::IdentityUnavailable)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|_| ResolutionError::IdentityDrift)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

#[cfg(target_os = "linux")]
fn directory_metadata(
    descriptor: &std::os::fd::OwnedFd,
) -> Result<std::fs::Metadata, ResolutionError> {
    let metadata = std::fs::File::from(
        descriptor
            .try_clone()
            .map_err(|_| ResolutionError::IdentityUnavailable)?,
    )
    .metadata()
    .map_err(|_| ResolutionError::IdentityUnavailable)?;
    if metadata.is_dir() {
        Ok(metadata)
    } else {
        Err(ResolutionError::ForbiddenFileKind)
    }
}

#[cfg(target_os = "linux")]
fn directory_metadata_changed(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}

#[cfg(target_os = "linux")]
fn path_bytes(path: &Path) -> &[u8] {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes()
}

#[cfg(target_os = "linux")]
fn require_rooted(path: &Path) -> Result<(), ResolutionError> {
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

#[cfg(target_os = "linux")]
fn require_external(path: &Path) -> Result<(), ResolutionError> {
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
