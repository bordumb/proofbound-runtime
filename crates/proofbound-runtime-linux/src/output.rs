//! Creates fresh output roots and identifies post-run regular-file outputs.

use core::fmt;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::path::Component;

use proofbound_runtime_core::{ArtifactIdentity, AuthorityPath};

#[cfg(target_os = "linux")]
use proofbound_runtime_core::ArtifactRole;

use crate::RootedPathResolver;

#[cfg(target_os = "linux")]
const EMPTY_OUTPUT_ROOT_DOMAIN: &[u8] = b"proofbound-runtime-empty-output-root/1\n";

/// Owns one fresh output-root descriptor for an execution attempt.
#[derive(Debug)]
pub struct FreshOutputRoot {
    requested_path: PathBuf,
    resolved_target: PathBuf,
    identity: ArtifactIdentity,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
    #[cfg(target_os = "linux")]
    root_stamp: MetadataStamp,
}

impl FreshOutputRoot {
    /// Atomically creates and opens an absent directory beneath the plan root.
    pub fn create(
        resolver: &RootedPathResolver,
        requested: &AuthorityPath,
    ) -> Result<Self, OutputRootError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;

            let requested_path = Path::new(requested.as_str());
            let (parent, leaf) = split_output_path(requested_path)?;
            let parent = crate::sys::openat2_directory(
                resolver.root_fd().as_raw_fd(),
                parent,
                crate::sys::RESOLVE_BENEATH
                    | crate::sys::RESOLVE_NO_MAGICLINKS
                    | crate::sys::RESOLVE_NO_SYMLINKS,
            )
            .map_err(map_parent_error)?;
            crate::sys::create_directory_at(parent.as_raw_fd(), leaf, 0o700)
                .map_err(map_creation_error)?;
            let descriptor = crate::sys::openat2_directory(
                parent.as_raw_fd(),
                leaf,
                crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
            )
            .map_err(|_| OutputRootError::OpenFailed)?;
            let root_stamp = metadata_stamp(&descriptor)?;
            if root_stamp.mode != 0o700 {
                return Err(OutputRootError::ModeInvalid);
            }
            require_empty(&descriptor)?;
            let identity = empty_root_identity(root_stamp.mode)?;
            let resolved_target = crate::resolve::descriptor_target(&descriptor)
                .map_err(|_| OutputRootError::IdentityUnavailable)?;
            Ok(Self {
                requested_path: requested_path.to_path_buf(),
                resolved_target,
                identity,
                descriptor,
                root_stamp,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (resolver, requested);
            Err(OutputRootError::UnsupportedOperatingSystem)
        }
    }

    /// Returns the relative path requested by the execution plan.
    #[must_use]
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    /// Returns the created target observed through the retained descriptor.
    #[must_use]
    pub fn resolved_target(&self) -> &Path {
        &self.resolved_target
    }

    /// Returns the domain-separated identity of the initially empty root.
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Confirms immediately before launch that the retained root is still empty.
    pub fn revalidate_empty(&self) -> Result<(), OutputRootError> {
        #[cfg(target_os = "linux")]
        {
            let current = metadata_stamp(&self.descriptor)?;
            if !self.root_stamp.same_object_and_mode(&current) {
                return Err(OutputRootError::IdentityDrift);
            }
            require_empty(&self.descriptor)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(OutputRootError::UnsupportedOperatingSystem)
        }
    }

    /// Inventories every regular file after execution using confined opens.
    pub fn inventory(&self) -> Result<OutputInventory, OutputRootError> {
        #[cfg(target_os = "linux")]
        {
            let current = metadata_stamp(&self.descriptor)?;
            if !self.root_stamp.same_object_and_mode(&current) {
                return Err(OutputRootError::IdentityDrift);
            }
            let mut entries = Vec::new();
            inventory_directory(&self.descriptor, Path::new(""), &mut entries)?;
            entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
            Ok(OutputInventory { entries })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(OutputRootError::UnsupportedOperatingSystem)
        }
    }

    /// Borrows the retained root descriptor for Landlock rule creation.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.descriptor.as_fd()
    }
}

/// Owns one identified output descriptor and its diagnostic relative path.
#[derive(Debug)]
pub struct OutputEntry {
    relative_path: PathBuf,
    resolved_target: PathBuf,
    identity: ArtifactIdentity,
    #[cfg(target_os = "linux")]
    descriptor: std::os::fd::OwnedFd,
}

impl OutputEntry {
    /// Returns diagnostic context; the path is not part of artifact identity.
    #[must_use]
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    /// Returns the target observed through the retained descriptor.
    #[must_use]
    pub fn resolved_target(&self) -> &Path {
        &self.resolved_target
    }

    /// Returns the exact output-byte identity.
    #[must_use]
    pub const fn identity(&self) -> &ArtifactIdentity {
        &self.identity
    }

    /// Confirms that the retained output bytes and metadata have not drifted.
    pub fn revalidate_identity(&self) -> Result<(), OutputRootError> {
        #[cfg(target_os = "linux")]
        {
            let identity =
                crate::resolve::identify_descriptor(&self.descriptor, ArtifactRole::OutputArtifact)
                    .map_err(map_identity_error)?;
            if identity == self.identity {
                Ok(())
            } else {
                Err(OutputRootError::IdentityDrift)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(OutputRootError::UnsupportedOperatingSystem)
        }
    }
}

/// Contains a deterministic post-run inventory of regular-file outputs.
#[derive(Debug)]
pub struct OutputInventory {
    entries: Vec<OutputEntry>,
}

impl OutputInventory {
    /// Returns entries ordered by diagnostic relative path.
    #[must_use]
    pub fn entries(&self) -> &[OutputEntry] {
        &self.entries
    }

    /// Returns receipt identities in canonical identity order.
    #[must_use]
    pub fn receipt_identities(&self) -> Vec<ArtifactIdentity> {
        let mut identities = self
            .entries
            .iter()
            .map(|entry| entry.identity.clone())
            .collect::<Vec<_>>();
        identities.sort();
        identities.dedup();
        identities
    }

    /// Revalidates all retained descriptors before receipt construction.
    pub fn revalidate_identities(&self) -> Result<(), OutputRootError> {
        for entry in &self.entries {
            entry.revalidate_identity()?;
        }
        Ok(())
    }
}

/// Identifies one fail-closed fresh-root or inventory result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputRootError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The requested output path was not a normalized relative child path.
    PathInvalid,
    /// The confined parent directory could not be opened.
    ParentUnavailable,
    /// The requested fresh output root already existed.
    AlreadyExists,
    /// The new directory could not be created.
    CreationFailed,
    /// The new directory could not be reopened by descriptor.
    OpenFailed,
    /// The output root did not have the required private mode.
    ModeInvalid,
    /// The newly created or pre-launch root was not empty.
    NotEmpty,
    /// A directory or file changed during inventory.
    IdentityDrift,
    /// A resolved output was not a regular file or directory.
    ForbiddenFileKind,
    /// Exact output identity could not be measured.
    IdentityUnavailable,
    /// The kernel cannot provide the required `openat2` guarantee.
    Openat2Unavailable,
}

impl OutputRootError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "output.os.unsupported",
            Self::PathInvalid => "output.path.invalid",
            Self::ParentUnavailable => "output.parent.unavailable",
            Self::AlreadyExists => "output.root.exists",
            Self::CreationFailed => "output.root.creation-failed",
            Self::OpenFailed => "output.root.open-failed",
            Self::ModeInvalid => "output.root.mode-invalid",
            Self::NotEmpty => "output.root.not-empty",
            Self::IdentityDrift => "output.identity.drift",
            Self::ForbiddenFileKind => "output.file-kind.forbidden",
            Self::IdentityUnavailable => "output.identity.unavailable",
            Self::Openat2Unavailable => "output.openat2.unavailable",
        }
    }
}

impl fmt::Display for OutputRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for OutputRootError {}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetadataStamp {
    device: u64,
    inode: u64,
    mode: u16,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "linux")]
impl MetadataStamp {
    fn same_object_and_mode(self, other: &Self) -> bool {
        self.device == other.device && self.inode == other.inode && self.mode == other.mode
    }
}

#[cfg(target_os = "linux")]
fn split_output_path(path: &Path) -> Result<(&Path, &Path), OutputRootError> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(OutputRootError::PathInvalid);
    }
    let leaf = path.file_name().ok_or(OutputRootError::PathInvalid)?;
    if leaf == "." || leaf == ".." {
        return Err(OutputRootError::PathInvalid);
    }
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((parent, Path::new(leaf)))
}

#[cfg(target_os = "linux")]
fn empty_root_identity(mode: u16) -> Result<ArtifactIdentity, OutputRootError> {
    use proofbound_runtime_core::{FileMode, Sha256Digest};
    use sha2::{Digest as _, Sha256};

    let mode = FileMode::new(mode).map_err(|_| OutputRootError::IdentityUnavailable)?;
    Ok(ArtifactIdentity::new(
        ArtifactRole::OutputRoot,
        Sha256Digest::from_bytes(Sha256::digest(EMPTY_OUTPUT_ROOT_DOMAIN).into()),
        0,
        mode,
    ))
}

#[cfg(target_os = "linux")]
fn require_empty(descriptor: &std::os::fd::OwnedFd) -> Result<(), OutputRootError> {
    if directory_names(descriptor)?.is_empty() {
        Ok(())
    } else {
        Err(OutputRootError::NotEmpty)
    }
}

#[cfg(target_os = "linux")]
fn inventory_directory(
    descriptor: &std::os::fd::OwnedFd,
    relative_parent: &Path,
    entries: &mut Vec<OutputEntry>,
) -> Result<(), OutputRootError> {
    use std::os::fd::AsRawFd as _;

    let before = metadata_stamp(descriptor)?;
    let names = directory_names(descriptor)?;
    for name in names {
        let path = Path::new(&name);
        let relative_path = relative_parent.join(path);
        let inspected = crate::sys::openat2_path(
            descriptor.as_raw_fd(),
            path,
            crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
        )
        .map_err(map_inventory_open_error)?;
        match classify_entry(&inspected)? {
            EntryKind::Directory(identity) => {
                let directory = crate::sys::openat2_directory(
                    descriptor.as_raw_fd(),
                    path,
                    crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
                )
                .map_err(map_inventory_open_error)?;
                require_same_object(identity, &directory)?;
                inventory_directory(&directory, &relative_path, entries)?;
            }
            EntryKind::RegularFile(identity) => {
                let file = crate::sys::openat2_file(
                    descriptor.as_raw_fd(),
                    path,
                    crate::sys::RESOLVE_NO_MAGICLINKS | crate::sys::RESOLVE_NO_SYMLINKS,
                )
                .map_err(map_inventory_open_error)?;
                require_same_object(identity, &file)?;
                let identity =
                    crate::resolve::identify_descriptor(&file, ArtifactRole::OutputArtifact)
                        .map_err(map_identity_error)?;
                let resolved_target = crate::resolve::descriptor_target(&file)
                    .map_err(|_| OutputRootError::IdentityUnavailable)?;
                entries.push(OutputEntry {
                    relative_path,
                    resolved_target,
                    identity,
                    descriptor: file,
                });
            }
        }
    }
    let after = metadata_stamp(descriptor)?;
    if before != after {
        return Err(OutputRootError::IdentityDrift);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum EntryKind {
    Directory(ObjectIdentity),
    RegularFile(ObjectIdentity),
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
fn classify_entry(descriptor: &std::os::fd::OwnedFd) -> Result<EntryKind, OutputRootError> {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt as _;

    let file = File::from(
        descriptor
            .try_clone()
            .map_err(|_| OutputRootError::IdentityUnavailable)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| OutputRootError::IdentityUnavailable)?;
    let identity = ObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    if metadata.is_dir() {
        Ok(EntryKind::Directory(identity))
    } else if metadata.is_file() {
        Ok(EntryKind::RegularFile(identity))
    } else {
        Err(OutputRootError::ForbiddenFileKind)
    }
}

#[cfg(target_os = "linux")]
fn require_same_object(
    expected: ObjectIdentity,
    descriptor: &std::os::fd::OwnedFd,
) -> Result<(), OutputRootError> {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt as _;

    let file = File::from(
        descriptor
            .try_clone()
            .map_err(|_| OutputRootError::IdentityUnavailable)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| OutputRootError::IdentityUnavailable)?;
    if metadata.dev() == expected.device && metadata.ino() == expected.inode {
        Ok(())
    } else {
        Err(OutputRootError::IdentityDrift)
    }
}

#[cfg(target_os = "linux")]
fn directory_names(
    descriptor: &std::os::fd::OwnedFd,
) -> Result<Vec<std::ffi::OsString>, OutputRootError> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;

    let path = format!("/proc/self/fd/{}", descriptor.as_raw_fd());
    let mut names = std::fs::read_dir(path)
        .map_err(|_| OutputRootError::IdentityUnavailable)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|_| OutputRootError::IdentityDrift)
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(names)
}

#[cfg(target_os = "linux")]
fn metadata_stamp(descriptor: &std::os::fd::OwnedFd) -> Result<MetadataStamp, OutputRootError> {
    use std::fs::File;
    use std::os::unix::fs::MetadataExt as _;

    let file = File::from(
        descriptor
            .try_clone()
            .map_err(|_| OutputRootError::IdentityUnavailable)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| OutputRootError::IdentityUnavailable)?;
    if !metadata.is_dir() {
        return Err(OutputRootError::ForbiddenFileKind);
    }
    Ok(MetadataStamp {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: u16::try_from(metadata.mode() & 0o7777)
            .map_err(|_| OutputRootError::IdentityUnavailable)?,
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(target_os = "linux")]
fn map_parent_error(error: std::io::Error) -> OutputRootError {
    if error.raw_os_error() == Some(libc::ENOSYS) {
        OutputRootError::Openat2Unavailable
    } else {
        OutputRootError::ParentUnavailable
    }
}

#[cfg(target_os = "linux")]
fn map_creation_error(error: std::io::Error) -> OutputRootError {
    if error.raw_os_error() == Some(libc::EEXIST) {
        OutputRootError::AlreadyExists
    } else {
        OutputRootError::CreationFailed
    }
}

#[cfg(target_os = "linux")]
fn map_inventory_open_error(error: std::io::Error) -> OutputRootError {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => OutputRootError::Openat2Unavailable,
        Some(libc::ELOOP | libc::ENXIO | libc::ENODEV) => OutputRootError::ForbiddenFileKind,
        Some(libc::ENOENT) => OutputRootError::IdentityDrift,
        _ => OutputRootError::IdentityUnavailable,
    }
}

#[cfg(target_os = "linux")]
fn map_identity_error(error: crate::ResolutionError) -> OutputRootError {
    match error {
        crate::ResolutionError::ForbiddenFileKind => OutputRootError::ForbiddenFileKind,
        crate::ResolutionError::IdentityDrift => OutputRootError::IdentityDrift,
        _ => OutputRootError::IdentityUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/authority/output-v1.toml"
    ));

    #[test]
    fn frozen_output_attack_catalog_is_closed() {
        let expected_ids = [
            "preexisting-output-root",
            "output-root-symlink-parent",
            "output-symlink",
            "output-special-file",
            "output-content-drift",
            "output-directory-drift",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-output-attacks/1\""));
        assert_eq!(
            ATTACK_CATALOG.matches("[[attack]]").count(),
            expected_ids.len()
        );
        for id in expected_ids {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn error_codes_are_unique_and_stable() {
        let errors = [
            OutputRootError::UnsupportedOperatingSystem,
            OutputRootError::PathInvalid,
            OutputRootError::ParentUnavailable,
            OutputRootError::AlreadyExists,
            OutputRootError::CreationFailed,
            OutputRootError::OpenFailed,
            OutputRootError::ModeInvalid,
            OutputRootError::NotEmpty,
            OutputRootError::IdentityDrift,
            OutputRootError::ForbiddenFileKind,
            OutputRootError::IdentityUnavailable,
            OutputRootError::Openat2Unavailable,
        ];
        let mut codes = errors.map(OutputRootError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_creation_is_never_positive_evidence() {
        let resolver = RootedPathResolver::open(Path::new("."));
        assert!(matches!(
            resolver,
            Err(crate::ResolutionError::UnsupportedOperatingSystem)
        ));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::sync::atomic::{AtomicU64, Ordering};

        use super::*;

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new(label: &str) -> Self {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "proofbound-runtime-output-{label}-{}-{sequence}",
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
        fn creates_private_fresh_root_and_inventories_regular_files() {
            let root = TestDirectory::new("inventory");
            fs::create_dir(root.0.join("outputs")).expect("create registered output parent");
            let resolver = RootedPathResolver::open(&root.0).expect("open plan root");
            let path = AuthorityPath::new("outputs/execution-1").expect("valid output path");
            let output = FreshOutputRoot::create(&resolver, &path).expect("create fresh root");
            assert_eq!(output.identity().role(), ArtifactRole::OutputRoot);
            assert_eq!(output.identity().mode().get(), 0o700);
            output.revalidate_empty().expect("root remains empty");

            fs::write(output.resolved_target().join("b"), b"second").expect("write output b");
            fs::write(output.resolved_target().join("a"), b"first").expect("write output a");
            let inventory = output.inventory().expect("inventory outputs");
            assert_eq!(inventory.entries().len(), 2);
            assert_eq!(inventory.entries()[0].relative_path(), Path::new("a"));
            assert_eq!(inventory.entries()[1].relative_path(), Path::new("b"));
            assert_eq!(inventory.receipt_identities().len(), 2);
            inventory
                .revalidate_identities()
                .expect("outputs remain exact");
        }

        #[test]
        fn rejects_preexisting_root_and_output_symlink() {
            let root = TestDirectory::new("attacks");
            fs::create_dir(root.0.join("outputs")).expect("create registered output parent");
            fs::create_dir(root.0.join("outputs/existing")).expect("create collision");
            let resolver = RootedPathResolver::open(&root.0).expect("open plan root");
            let existing = AuthorityPath::new("outputs/existing").expect("valid output path");
            assert!(matches!(
                FreshOutputRoot::create(&resolver, &existing),
                Err(OutputRootError::AlreadyExists)
            ));

            let fresh = AuthorityPath::new("outputs/fresh").expect("valid output path");
            let output = FreshOutputRoot::create(&resolver, &fresh).expect("create fresh root");
            symlink("/etc/passwd", output.resolved_target().join("link"))
                .expect("create output symlink");
            assert!(matches!(
                output.inventory(),
                Err(OutputRootError::ForbiddenFileKind)
            ));
        }

        #[test]
        fn retained_output_descriptor_detects_content_drift() {
            let root = TestDirectory::new("drift");
            fs::create_dir(root.0.join("outputs")).expect("create registered output parent");
            fs::set_permissions(root.0.join("outputs"), fs::Permissions::from_mode(0o700))
                .expect("set parent mode");
            let resolver = RootedPathResolver::open(&root.0).expect("open plan root");
            let path = AuthorityPath::new("outputs/fresh").expect("valid output path");
            let output = FreshOutputRoot::create(&resolver, &path).expect("create fresh root");
            let artifact = output.resolved_target().join("result");
            fs::write(&artifact, b"original").expect("write output");
            let inventory = output.inventory().expect("inventory outputs");
            fs::write(&artifact, b"changed").expect("replace bytes in place");
            assert_eq!(
                inventory.entries()[0].revalidate_identity(),
                Err(OutputRootError::IdentityDrift)
            );
        }
    }
}
