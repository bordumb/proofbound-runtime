#![forbid(unsafe_code)]

//! Defines the pure domain model for Proofbound Runtime.

mod authority;
mod diagnostic;
mod error;
mod identity;
mod network;
mod normalize;
mod outcome;
mod plan;
mod policy;
mod receipt;
mod run_result;
mod wire_v2;

pub use authority::{
    AuthorityError, AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, MemoryByteLimit,
    NetworkMode, OutputByteLimit, PathAuthority, PathRole, ProcessLimit, ResourceLimits,
    SwapByteLimit, WallTimeLimit,
};
pub use diagnostic::{
    DiagnosticCompletion, DiagnosticObserverMechanism, DiagnosticTypeError, DraftProvenance,
    ExecutionProfile, ObservationResolution,
};
pub use error::{CoreError, ErrorClass, MachineError};
pub use identity::{ArtifactIdentity, ArtifactRole, FileMode, IdentityError, Sha256Digest};
pub use network::{
    AddressOrder, AuthenticatedServiceSession, ChildChannelDescriptor, CredentialSource,
    CredentialSourceId, LocalChannelProtocol, MinimumTlsVersion, NetworkAuthorityError,
    NetworkSupportPath, ResolutionPolicy, ResolverAddress, ResolverEndpoint, RevocationPolicy,
    ServiceName, ServiceNameVerification, ServiceSessionLimits, TcpPort, TlsPolicy,
};
pub use normalize::{NormalizedAuthority, normalize_authority};
pub use outcome::{ExecutionOutcome, ExecutionOutcomeKind, SignalNumber, execution_outcome_kind};
pub use plan::{
    CommandArgument, ExecutionCommand, ExecutionPlan, PlanError, PlanId, ServiceExecutionPlan,
    parse_execution_plan, parse_execution_plan_for_execution, parse_service_execution_plan,
};
pub use policy::{
    CgroupPolicy, CompiledPolicy, FilesystemPolicy, NoNewPrivileges, PolicyEncodingError,
    SeccompPolicy, compile_policy,
};
pub use receipt::{
    Architecture, BoundaryInstallation, BoundaryRecord, CgroupIdentity, EXECUTION_RECEIPT_SCHEMA,
    ExecutionId, ExecutionObservations, ExecutionReceipt, ExecutionReceiptParts, LimitEvent,
    LimitEvents, NonReusableReason, NonReusableReasons, POLICY_MODEL_VERSION, PlatformIdentity,
    REQUIRED_RUNTIME_ASSUMPTIONS, ReceiptArtifactField, ReceiptCommand, ReceiptConfiguredResources,
    ReceiptEligibility, ReceiptError, ReceiptFacts, ReceiptIdentityField, ReceiptMemoryEvents,
    ReceiptPlan, ReceiptPolicy, ReceiptResources, ReceiptStreams, ReceiptStructure,
    ReceiptSwapEvents, RuntimeIdentity, StreamCapture, TrustedComputingBaseEntry,
    TrustedComputingBaseRole, construct_execution_receipt, derive_receipt_eligibility,
};
pub use run_result::{RunResultError, RunResultV2};
