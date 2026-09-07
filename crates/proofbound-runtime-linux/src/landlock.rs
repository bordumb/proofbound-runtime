//! Installs the closed version 1 Landlock filesystem boundary.

use core::fmt;
use core::num::NonZeroU32;
use std::os::fd::BorrowedFd;

use crate::LockedPrivileges;

#[cfg(any(test, target_os = "linux"))]
const ACCESS_EXECUTE: u64 = 1 << 0;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_WRITE_FILE: u64 = 1 << 1;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_READ_FILE: u64 = 1 << 2;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_READ_DIR: u64 = 1 << 3;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_REMOVE_DIR: u64 = 1 << 4;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_CHAR: u64 = 1 << 6;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_DIR: u64 = 1 << 7;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_REG: u64 = 1 << 8;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_BLOCK: u64 = 1 << 11;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_MAKE_SYM: u64 = 1 << 12;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_REFER: u64 = 1 << 13;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_TRUNCATE: u64 = 1 << 14;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_IOCTL_DEV: u64 = 1 << 15;
#[cfg(any(test, target_os = "linux"))]
const ACCESS_RESOLVE_UNIX: u64 = 1 << 16;
#[cfg(target_os = "linux")]
const MAX_REVIEWED_ABI: u32 = 11;

#[cfg(any(test, target_os = "linux"))]
const ACCESS_WRITE_DIRECTORY: u64 = ACCESS_WRITE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM
    | ACCESS_REFER
    | ACCESS_TRUNCATE;

/// Selects one closed filesystem authority class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LandlockAccess {
    /// Permits file bytes and directory enumeration beneath a descriptor.
    Read,
    /// Permits mutation beneath a directory or of one exact file.
    Write,
    /// Permits execution of one exact regular file.
    Execute,
}

/// Borrows one already-resolved descriptor with its intended authority class.
#[derive(Debug)]
pub struct LandlockRule<'descriptor> {
    descriptor: BorrowedFd<'descriptor>,
    access: LandlockAccess,
}

impl<'descriptor> LandlockRule<'descriptor> {
    /// Creates a rule from a descriptor retained by the resolution boundary.
    #[must_use]
    pub const fn new(descriptor: BorrowedFd<'descriptor>, access: LandlockAccess) -> Self {
        Self { descriptor, access }
    }

    /// Returns the requested authority class.
    #[must_use]
    pub const fn access(&self) -> LandlockAccess {
        self.access
    }

    /// Returns the already-resolved descriptor borrowed by this rule.
    #[must_use]
    pub const fn descriptor(&self) -> BorrowedFd<'descriptor> {
        self.descriptor
    }
}

/// Witnesses successful installation of every registered Landlock rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LandlockBoundary {
    abi: NonZeroU32,
    handled_access_fs: u64,
    rule_count: usize,
}

impl LandlockBoundary {
    /// Returns the exact kernel ABI used to compile the ruleset.
    #[must_use]
    pub const fn abi(self) -> NonZeroU32 {
        self.abi
    }

    /// Returns the complete filesystem access mask handled by the ruleset.
    #[must_use]
    pub const fn handled_access_fs(self) -> u64 {
        self.handled_access_fs
    }

    /// Returns the number of successfully installed descriptor rules.
    #[must_use]
    pub const fn rule_count(self) -> usize {
        self.rule_count
    }
}

/// Installs a deny-by-default filesystem ruleset for the current launcher.
///
/// The locked-privilege witness ensures `no_new_privs` was observed before the
/// irreversible `landlock_restrict_self` call.
pub fn install_landlock(
    abi: NonZeroU32,
    _locked: &LockedPrivileges,
    rules: &[LandlockRule<'_>],
) -> Result<LandlockBoundary, LandlockError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;

        if !(3..=MAX_REVIEWED_ABI).contains(&abi.get()) {
            return Err(LandlockError::AbiUnsupported);
        }
        if rules.is_empty() {
            return Err(LandlockError::RuleSetEmpty);
        }
        let handled_access_fs = handled_access(abi);
        let ruleset = crate::sys::create_landlock_ruleset(handled_access_fs)
            .map_err(|_| LandlockError::RuleSetCreationFailed)?;
        for rule in rules {
            let is_directory = descriptor_is_directory(rule.descriptor)?;
            let allowed_access = allowed_access(rule.access, is_directory)?;
            crate::sys::add_landlock_path_rule(
                ruleset.as_raw_fd(),
                rule.descriptor.as_raw_fd(),
                allowed_access,
            )
            .map_err(|_| LandlockError::RuleInstallationFailed)?;
        }
        crate::sys::restrict_with_landlock(ruleset.as_raw_fd())
            .map_err(|_| LandlockError::RestrictionFailed)?;
        Ok(LandlockBoundary {
            abi,
            handled_access_fs,
            rule_count: rules.len(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (abi, rules);
        Err(LandlockError::UnsupportedOperatingSystem)
    }
}

/// Identifies one fail-closed Landlock installation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LandlockError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// The kernel ABI cannot mediate truncate operations.
    AbiUnsupported,
    /// No filesystem authority descriptors were supplied.
    RuleSetEmpty,
    /// A descriptor did not refer to a regular file or directory.
    FileKindInvalid,
    /// Execute authority was attached to a directory.
    DirectoryExecuteForbidden,
    /// The kernel ruleset descriptor could not be created.
    RuleSetCreationFailed,
    /// One descriptor rule could not be installed.
    RuleInstallationFailed,
    /// The current launcher could not be restricted by the completed ruleset.
    RestrictionFailed,
}

impl LandlockError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "landlock.os.unsupported",
            Self::AbiUnsupported => "landlock.abi.unsupported",
            Self::RuleSetEmpty => "landlock.rules.empty",
            Self::FileKindInvalid => "landlock.file-kind.invalid",
            Self::DirectoryExecuteForbidden => "landlock.execute.directory-forbidden",
            Self::RuleSetCreationFailed => "landlock.ruleset.creation-failed",
            Self::RuleInstallationFailed => "landlock.rule.installation-failed",
            Self::RestrictionFailed => "landlock.restriction.failed",
        }
    }
}

impl fmt::Display for LandlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for LandlockError {}

#[cfg(any(test, target_os = "linux"))]
const fn handled_access(abi: NonZeroU32) -> u64 {
    let mut access = ACCESS_EXECUTE
        | ACCESS_WRITE_FILE
        | ACCESS_READ_FILE
        | ACCESS_READ_DIR
        | ACCESS_REMOVE_DIR
        | ACCESS_REMOVE_FILE
        | ACCESS_MAKE_CHAR
        | ACCESS_MAKE_DIR
        | ACCESS_MAKE_REG
        | ACCESS_MAKE_SOCK
        | ACCESS_MAKE_FIFO
        | ACCESS_MAKE_BLOCK
        | ACCESS_MAKE_SYM
        | ACCESS_REFER
        | ACCESS_TRUNCATE;
    if abi.get() >= 5 {
        access |= ACCESS_IOCTL_DEV;
    }
    if abi.get() >= 9 {
        access |= ACCESS_RESOLVE_UNIX;
    }
    access
}

#[cfg(any(test, target_os = "linux"))]
const fn allowed_access(access: LandlockAccess, is_directory: bool) -> Result<u64, LandlockError> {
    match (access, is_directory) {
        (LandlockAccess::Read, true) => Ok(ACCESS_READ_FILE | ACCESS_READ_DIR),
        (LandlockAccess::Read, false) => Ok(ACCESS_READ_FILE),
        (LandlockAccess::Write, true) => Ok(ACCESS_WRITE_DIRECTORY),
        (LandlockAccess::Write, false) => Ok(ACCESS_WRITE_FILE | ACCESS_TRUNCATE),
        (LandlockAccess::Execute, false) => Ok(ACCESS_EXECUTE),
        (LandlockAccess::Execute, true) => Err(LandlockError::DirectoryExecuteForbidden),
    }
}

#[cfg(target_os = "linux")]
fn descriptor_is_directory(descriptor: BorrowedFd<'_>) -> Result<bool, LandlockError> {
    use std::fs::File;

    let file = File::from(
        descriptor
            .try_clone_to_owned()
            .map_err(|_| LandlockError::FileKindInvalid)?,
    );
    let metadata = file
        .metadata()
        .map_err(|_| LandlockError::FileKindInvalid)?;
    if metadata.is_dir() {
        Ok(true)
    } else if metadata.is_file() {
        Ok(false)
    } else {
        Err(LandlockError::FileKindInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/landlock/filesystem-v1.toml"
    ));

    fn abi(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("test ABI is nonzero")
    }

    #[test]
    fn access_masks_do_not_amplify_file_rules() {
        assert_eq!(
            allowed_access(LandlockAccess::Read, false),
            Ok(ACCESS_READ_FILE)
        );
        assert_eq!(
            allowed_access(LandlockAccess::Write, false),
            Ok(ACCESS_WRITE_FILE | ACCESS_TRUNCATE)
        );
        assert_eq!(
            allowed_access(LandlockAccess::Execute, false),
            Ok(ACCESS_EXECUTE)
        );
        assert_eq!(
            allowed_access(LandlockAccess::Execute, true),
            Err(LandlockError::DirectoryExecuteForbidden)
        );
    }

    #[test]
    fn handled_mask_tracks_kernel_abi_without_omitting_truncate() {
        assert_ne!(handled_access(abi(3)) & ACCESS_TRUNCATE, 0);
        assert_eq!(handled_access(abi(3)) & ACCESS_IOCTL_DEV, 0);
        assert_ne!(handled_access(abi(5)) & ACCESS_IOCTL_DEV, 0);
        assert_ne!(handled_access(abi(9)) & ACCESS_RESOLVE_UNIX, 0);
        assert_eq!(
            allowed_access(LandlockAccess::Write, true).expect("directory write mask")
                & !handled_access(abi(3)),
            0
        );
    }

    #[test]
    fn frozen_landlock_attack_catalog_is_closed() {
        let expected_ids = [
            "missing-read-rule",
            "undeclared-read",
            "undeclared-write",
            "write-root-escape",
            "directory-execute-amplification",
            "truncate-with-old-abi",
            "restriction-omitted",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-landlock-attacks/1\""));
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
            LandlockError::UnsupportedOperatingSystem,
            LandlockError::AbiUnsupported,
            LandlockError::RuleSetEmpty,
            LandlockError::FileKindInvalid,
            LandlockError::DirectoryExecuteForbidden,
            LandlockError::RuleSetCreationFailed,
            LandlockError::RuleInstallationFailed,
            LandlockError::RestrictionFailed,
        ];
        let mut codes = errors.map(LandlockError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
