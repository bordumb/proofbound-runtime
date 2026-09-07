#![forbid(unsafe_code)]

//! Defines the pure domain model for Proofbound Runtime.

mod authority;
mod identity;
mod normalize;
mod plan;
mod policy;
mod receipt;

pub use authority::{
    AuthorityError, AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, NetworkMode,
    OutputByteLimit, PathAuthority, PathRole, ProcessLimit, ResourceLimits, WallTimeLimit,
};
pub use identity::{ArtifactIdentity, ArtifactRole, FileMode, IdentityError, Sha256Digest};
pub use normalize::{NormalizedAuthority, normalize_authority};
pub use plan::{
    CommandArgument, ExecutionCommand, ExecutionPlan, PlanError, PlanId, parse_execution_plan,
};
pub use policy::{CgroupPolicy, CompiledPolicy, FilesystemPolicy, NoNewPrivileges, SeccompPolicy};
pub use receipt::{
    BoundaryInstallation, ExecutionOutcome, NonReusableReason, NonReusableReasons,
    ReceiptEligibility, ReceiptFacts, ReceiptStructure, SignalNumber, StreamCapture,
    derive_receipt_eligibility,
};
