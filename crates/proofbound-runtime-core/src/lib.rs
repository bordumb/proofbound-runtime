#![forbid(unsafe_code)]

//! Defines the pure domain model for Proofbound Runtime.

mod authority;
mod normalize;

pub use authority::{
    AuthorityError, AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, NetworkMode,
    OutputByteLimit, PathAuthority, PathRole, ProcessLimit, ResourceLimits, WallTimeLimit,
};
pub use normalize::{NormalizedAuthority, normalize_authority};
