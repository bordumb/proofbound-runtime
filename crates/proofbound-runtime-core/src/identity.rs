use core::fmt;

/// Identifies the security role of one artifact.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactRole {
    /// Contains the source execution plan.
    ExecutionPlan,
    /// Contains the normalized execution plan.
    NormalizedPlan,
    /// Contains the compiled platform policy.
    CompiledPolicy,
    /// Contains the runtime binary.
    RuntimeBinary,
    /// Contains the launcher binary.
    LauncherBinary,
    /// Contains the independent verifier binary.
    VerifierBinary,
    /// Contains the command executable.
    RuntimeExecutable,
    /// Contains the command loader executable.
    RuntimeLoaderExecutable,
    /// Contains one runtime library.
    RuntimeLibrary,
    /// Identifies the working directory inventory.
    WorkingDirectory,
    /// Contains one registered project input.
    ProjectInput,
    /// Identifies the fresh output-root inventory.
    OutputRoot,
    /// Contains captured standard output.
    StandardOutput,
    /// Contains captured standard error.
    StandardError,
    /// Contains one produced output artifact.
    OutputArtifact,
}

impl ArtifactRole {
    /// Parses one closed version 1 artifact role.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        match value {
            "execution-plan" => Ok(Self::ExecutionPlan),
            "normalized-plan" => Ok(Self::NormalizedPlan),
            "compiled-policy" => Ok(Self::CompiledPolicy),
            "runtime-binary" => Ok(Self::RuntimeBinary),
            "launcher-binary" => Ok(Self::LauncherBinary),
            "verifier-binary" => Ok(Self::VerifierBinary),
            "runtime-executable" => Ok(Self::RuntimeExecutable),
            "runtime-loader-executable" => Ok(Self::RuntimeLoaderExecutable),
            "runtime-library" => Ok(Self::RuntimeLibrary),
            "working-directory" => Ok(Self::WorkingDirectory),
            "project-input" => Ok(Self::ProjectInput),
            "output-root" => Ok(Self::OutputRoot),
            "standard-output" => Ok(Self::StandardOutput),
            "standard-error" => Ok(Self::StandardError),
            "output-artifact" => Ok(Self::OutputArtifact),
            _ => Err(IdentityError::UnsupportedRole),
        }
    }

    /// Returns the stable version 1 wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionPlan => "execution-plan",
            Self::NormalizedPlan => "normalized-plan",
            Self::CompiledPolicy => "compiled-policy",
            Self::RuntimeBinary => "runtime-binary",
            Self::LauncherBinary => "launcher-binary",
            Self::VerifierBinary => "verifier-binary",
            Self::RuntimeExecutable => "runtime-executable",
            Self::RuntimeLoaderExecutable => "runtime-loader-executable",
            Self::RuntimeLibrary => "runtime-library",
            Self::WorkingDirectory => "working-directory",
            Self::ProjectInput => "project-input",
            Self::OutputRoot => "output-root",
            Self::StandardOutput => "standard-output",
            Self::StandardError => "standard-error",
            Self::OutputArtifact => "output-artifact",
        }
    }
}

/// Contains an exact SHA-256 digest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Creates a digest from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses 64 lowercase hexadecimal characters.
    pub fn parse_hex(value: &str) -> Result<Self, IdentityError> {
        let input = value.as_bytes();
        if input.len() != 64 {
            return Err(IdentityError::DigestLength);
        }
        let mut bytes = [0_u8; 32];
        let mut index = 0;
        while index < bytes.len() {
            bytes[index] = (hex_nibble(input[index * 2])? << 4) | hex_nibble(input[index * 2 + 1])?;
            index += 1;
        }
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

fn hex_nibble(value: u8) -> Result<u8, IdentityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(IdentityError::DigestCharacter),
    }
}

/// Contains version 1 Unix permission bits.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileMode(u16);

impl FileMode {
    /// Validates permission and special-mode bits.
    pub fn new(value: u16) -> Result<Self, IdentityError> {
        if value > 0o7777 {
            return Err(IdentityError::ModeRange);
        }
        Ok(Self(value))
    }

    /// Returns the validated mode bits.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Contains the complete version 1 identity of one artifact role.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactIdentity {
    role: ArtifactRole,
    digest: Sha256Digest,
    size: u64,
    mode: FileMode,
}

impl ArtifactIdentity {
    /// Creates one complete typed artifact identity.
    #[must_use]
    pub const fn new(role: ArtifactRole, digest: Sha256Digest, size: u64, mode: FileMode) -> Self {
        Self {
            role,
            digest,
            size,
            mode,
        }
    }

    /// Returns the artifact role.
    #[must_use]
    pub const fn role(&self) -> ArtifactRole {
        self.role
    }

    /// Returns the SHA-256 digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the byte size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Returns the Unix mode bits.
    #[must_use]
    pub const fn mode(&self) -> FileMode {
        self.mode
    }
}

/// Identifies invalid artifact identity input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// The role is outside the closed version 1 role set.
    UnsupportedRole,
    /// The digest does not contain exactly 64 characters.
    DigestLength,
    /// The digest contains a non-lowercase-hexadecimal character.
    DigestCharacter,
    /// The mode contains bits outside the version 1 range.
    ModeRange,
}

impl IdentityError {
    /// Returns the stable machine code for this error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedRole => "identity.role.unsupported",
            Self::DigestLength => "identity.digest.length",
            Self::DigestCharacter => "identity.digest.character",
            Self::ModeRange => "identity.mode.range",
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_round_trip_is_exact() {
        let text = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let digest = Sha256Digest::parse_hex(text).expect("fixture is lowercase SHA-256");
        assert_eq!(digest.to_hex(), text);
    }

    #[test]
    fn rejects_noncanonical_digest_text() {
        assert_eq!(
            Sha256Digest::parse_hex("00"),
            Err(IdentityError::DigestLength)
        );
        assert_eq!(
            Sha256Digest::parse_hex(
                "A123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Err(IdentityError::DigestCharacter)
        );
    }

    #[test]
    fn every_role_round_trips_through_its_wire_name() {
        let roles = [
            ArtifactRole::ExecutionPlan,
            ArtifactRole::NormalizedPlan,
            ArtifactRole::CompiledPolicy,
            ArtifactRole::RuntimeBinary,
            ArtifactRole::LauncherBinary,
            ArtifactRole::VerifierBinary,
            ArtifactRole::RuntimeExecutable,
            ArtifactRole::RuntimeLoaderExecutable,
            ArtifactRole::RuntimeLibrary,
            ArtifactRole::WorkingDirectory,
            ArtifactRole::ProjectInput,
            ArtifactRole::OutputRoot,
            ArtifactRole::StandardOutput,
            ArtifactRole::StandardError,
            ArtifactRole::OutputArtifact,
        ];
        for role in roles {
            assert_eq!(ArtifactRole::parse(role.as_str()), Ok(role));
        }
        assert_eq!(
            ArtifactRole::parse("other"),
            Err(IdentityError::UnsupportedRole)
        );
    }

    #[test]
    fn rejects_mode_bits_outside_the_wire_contract() {
        assert_eq!(FileMode::new(0o7777).map(FileMode::get), Ok(0o7777));
        assert_eq!(FileMode::new(0o10000), Err(IdentityError::ModeRange));
    }
}
