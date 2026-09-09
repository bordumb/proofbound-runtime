#![forbid(unsafe_code)]

//! Defines the pure domain model for Proofbound Runtime.

mod authority;
mod error;
mod identity;
mod normalize;
mod outcome;
mod plan;
mod policy;
mod receipt;

pub use authority::{
    AuthorityError, AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, NetworkMode,
    OutputByteLimit, PathAuthority, PathRole, ProcessLimit, ResourceLimits, WallTimeLimit,
};
pub use error::{CoreError, ErrorClass, MachineError};
pub use identity::{ArtifactIdentity, ArtifactRole, FileMode, IdentityError, Sha256Digest};
pub use normalize::{NormalizedAuthority, normalize_authority};
pub use outcome::{ExecutionOutcome, ExecutionOutcomeKind, SignalNumber, execution_outcome_kind};
pub use plan::{
    CommandArgument, ExecutionCommand, ExecutionPlan, PlanError, PlanId, parse_execution_plan,
};
pub use policy::{
    CgroupPolicy, CompiledPolicy, FilesystemPolicy, NoNewPrivileges, SeccompPolicy, compile_policy,
};
pub use receipt::{
    Architecture, BoundaryInstallation, BoundaryRecord, CgroupIdentity, EXECUTION_RECEIPT_SCHEMA,
    ExecutionId, ExecutionObservations, ExecutionReceipt, ExecutionReceiptParts, NonReusableReason,
    NonReusableReasons, POLICY_MODEL_VERSION, PlatformIdentity, REQUIRED_RUNTIME_ASSUMPTIONS,
    ReceiptArtifactField, ReceiptCommand, ReceiptEligibility, ReceiptError, ReceiptFacts,
    ReceiptIdentityField, ReceiptPlan, ReceiptPolicy, ReceiptStreams, ReceiptStructure,
    RuntimeIdentity, StreamCapture, TrustedComputingBaseEntry, TrustedComputingBaseRole,
    construct_execution_receipt, derive_receipt_eligibility,
};
