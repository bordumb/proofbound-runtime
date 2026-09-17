//! Constructs a reviewable plan draft from one diagnostic receipt.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use proofbound_runtime_core::{DraftProvenance, ObservationResolution, Sha256Digest};
use serde_json::{Value, json};

use crate::artifact::{
    DiagnosticEvent, DiagnosticEventClass, DiagnosticReceipt, ObservationOutcome,
    is_normalized_absolute_path,
};
use crate::canonical::{BoundedCanonicalJson, CanonicalWriteError};

/// Identifies the plan-draft schema.
pub const PLAN_DRAFT_SCHEMA: &str = "proofbound-runtime-plan-draft/1";

/// Contains a digest and size without assigning Runtime artifact authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContentIdentity {
    digest: Sha256Digest,
    size_bytes: u64,
}

impl ContentIdentity {
    /// Creates one exact content identity.
    #[must_use]
    pub const fn new(digest: Sha256Digest, size_bytes: u64) -> Self {
        Self { digest, size_bytes }
    }

    fn to_value(self) -> Value {
        json!({
            "sha256": format!("sha256:{}", self.digest.to_hex()),
            "size_bytes": self.size_bytes,
        })
    }
}

/// Contains one exact project input retained by the draft.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DraftInput {
    path: String,
    identity: ContentIdentity,
    mode: u16,
}

impl DraftInput {
    /// Creates one absolute identified project input.
    pub fn new(
        path: impl Into<String>,
        identity: ContentIdentity,
        mode: u16,
    ) -> Result<Self, DraftError> {
        let path = path.into();
        validate_absolute_path(&path).map_err(|_| DraftError::InputInvalid)?;
        if mode > 0o7777 {
            return Err(DraftError::InputInvalid);
        }
        Ok(Self {
            path,
            identity,
            mode,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "mode": format!("{:04o}", self.mode),
            "path": self.path,
            "role": "project-input",
            "sha256": format!("sha256:{}", self.identity.digest.to_hex()),
            "size_bytes": self.identity.size_bytes,
        })
    }
}

/// Identifies one exact file role in a static execution closure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IdentifiedClosureRole {
    /// Contains the workload executable.
    Executable,
    /// Contains the workload interpreter.
    Interpreter,
    /// Contains one runtime library.
    RuntimeLibrary,
}

impl IdentifiedClosureRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Interpreter => "interpreter",
            Self::RuntimeLibrary => "runtime-library",
        }
    }
}

/// Contains one exact non-authoritative static closure observation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IdentifiedClosureEntry {
    role: IdentifiedClosureRole,
    path: String,
    identity: ContentIdentity,
    mode: u16,
    provenance: DraftProvenance,
}

impl IdentifiedClosureEntry {
    /// Creates one exact closure observation. This value does not grant authority.
    pub fn new(
        role: IdentifiedClosureRole,
        path: impl Into<String>,
        identity: ContentIdentity,
        mode: u16,
        provenance: DraftProvenance,
    ) -> Result<Self, DraftError> {
        let path = path.into();
        validate_absolute_path(&path).map_err(|_| DraftError::ClosureInvalid)?;
        if mode > 0o7777
            || !matches!(
                (role, provenance),
                (
                    IdentifiedClosureRole::Executable,
                    DraftProvenance::StaticExecutableClosure
                ) | (
                    IdentifiedClosureRole::Interpreter | IdentifiedClosureRole::RuntimeLibrary,
                    DraftProvenance::PlatformRequiredClosure
                )
            )
        {
            return Err(DraftError::ClosureInvalid);
        }
        Ok(Self {
            role,
            path,
            identity,
            mode,
            provenance,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "mode": format!("{:04o}", self.mode),
            "path": self.path,
            "provenance": self.provenance.as_str(),
            "role": self.role.as_str(),
            "sha256": format!("sha256:{}", self.identity.digest.to_hex()),
            "size_bytes": self.identity.size_bytes,
        })
    }
}

/// Restricts automatic candidates to reviewed project or runtime closures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftPathScope {
    candidate_roots: BTreeSet<String>,
    excluded_roots: BTreeSet<String>,
}

impl DraftPathScope {
    /// Creates one exact candidate scope with explicit home and temporary roots.
    pub fn new(
        candidate_roots: impl IntoIterator<Item = String>,
        home_directory: String,
        temporary_roots: impl IntoIterator<Item = String>,
    ) -> Result<Self, DraftError> {
        let candidate_roots = canonical_path_set(candidate_roots, false)?;
        if candidate_roots.is_empty() {
            return Err(DraftError::PathScopeInvalid);
        }
        validate_absolute_path(&home_directory)?;
        if home_directory == "/" {
            return Err(DraftError::PathScopeInvalid);
        }
        let mut excluded_roots = canonical_path_set(temporary_roots, true)?;
        excluded_roots.insert(home_directory);
        if candidate_roots.iter().any(|root| {
            is_system_path(root)
                || excluded_roots
                    .iter()
                    .any(|excluded| path_is_within(root, excluded))
        }) {
            return Err(DraftError::PathScopeInvalid);
        }
        Ok(Self {
            candidate_roots,
            excluded_roots,
        })
    }

    fn allows(&self, path: &str) -> bool {
        is_normalized_absolute_path(path)
            && !is_system_path(path)
            && !self
                .excluded_roots
                .iter()
                .any(|root| path_is_within(path, root))
            && self
                .candidate_roots
                .iter()
                .any(|root| path_is_within(path, root))
    }
}

/// Identifies whether a Capsec report can participate in comparison.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapsecUsability {
    /// The analyzer identity is not accepted.
    AnalyzerUnknown,
    /// The report declares incomplete coverage.
    Incomplete,
    /// The report bytes or structure are invalid.
    ReportInvalid,
    /// The schema identity is not accepted.
    SchemaUnknown,
    /// The report identifies different source bytes.
    SourceStale,
    /// Every selected Capsec identity matches the integration profile.
    Usable,
}

impl CapsecUsability {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AnalyzerUnknown => "analyzer-unknown",
            Self::Incomplete => "incomplete",
            Self::ReportInvalid => "report-invalid",
            Self::SchemaUnknown => "schema-unknown",
            Self::SourceStale => "source-stale",
            Self::Usable => "usable",
        }
    }
}

/// Contains the exact Capsec identities selected by one integration profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsecIntegrationProfile {
    schema_identity: String,
    source: ContentIdentity,
    analyzer: ContentIdentity,
    report: ContentIdentity,
}

impl CapsecIntegrationProfile {
    /// Creates one exact accepted Capsec tuple.
    pub fn new(
        schema_identity: impl Into<String>,
        source: ContentIdentity,
        analyzer: ContentIdentity,
        report: ContentIdentity,
    ) -> Result<Self, DraftError> {
        let schema_identity = schema_identity.into();
        if !valid_schema_identity(&schema_identity) {
            return Err(DraftError::CapsecInvalid);
        }
        Ok(Self {
            schema_identity,
            source,
            analyzer,
            report,
        })
    }
}

/// Contains one parsed Capsec report observation before usability is derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsecReportObservation {
    schema_identity: String,
    source: ContentIdentity,
    analyzer: ContentIdentity,
    report: ContentIdentity,
    structurally_valid: bool,
    complete: bool,
}

impl CapsecReportObservation {
    /// Creates one identified report observation.
    pub fn new(
        schema_identity: impl Into<String>,
        source: ContentIdentity,
        analyzer: ContentIdentity,
        report: ContentIdentity,
        structurally_valid: bool,
        complete: bool,
    ) -> Result<Self, DraftError> {
        let schema_identity = schema_identity.into();
        if !valid_schema_identity(&schema_identity) {
            return Err(DraftError::CapsecInvalid);
        }
        Ok(Self {
            schema_identity,
            source,
            analyzer,
            report,
            structurally_valid,
            complete,
        })
    }
}

/// Contains exact Capsec input identities and their derived usability result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsecInput {
    schema_identity: String,
    source: ContentIdentity,
    analyzer: ContentIdentity,
    report: ContentIdentity,
    usability: CapsecUsability,
}

impl CapsecInput {
    /// Derives usability from one selected profile and one report observation.
    #[must_use]
    pub fn evaluate(
        profile: &CapsecIntegrationProfile,
        observation: CapsecReportObservation,
    ) -> Self {
        let usability = if observation.schema_identity != profile.schema_identity {
            CapsecUsability::SchemaUnknown
        } else if observation.source != profile.source {
            CapsecUsability::SourceStale
        } else if observation.analyzer != profile.analyzer {
            CapsecUsability::AnalyzerUnknown
        } else if observation.report != profile.report || !observation.structurally_valid {
            CapsecUsability::ReportInvalid
        } else if !observation.complete {
            CapsecUsability::Incomplete
        } else {
            CapsecUsability::Usable
        };
        Self {
            schema_identity: observation.schema_identity,
            source: observation.source,
            analyzer: observation.analyzer,
            report: observation.report,
            usability,
        }
    }

    /// Returns the derived usability result.
    #[must_use]
    pub const fn usability(&self) -> CapsecUsability {
        self.usability
    }

    fn to_value(&self) -> Value {
        json!({
            "analyzer": self.analyzer.to_value(),
            "report": self.report.to_value(),
            "schema_identity": self.schema_identity,
            "source": self.source.to_value(),
            "usability": self.usability.as_str(),
        })
    }
}

/// Identifies one cross-project comparison class.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DifferenceClass {
    /// Capsec names a requirement for which Runtime grants no authority.
    RequirementWithoutRuntimeAuthority,
    /// Runtime grants authority that neither Capsec nor observation requires.
    RuntimeAuthorityWithoutRequirementOrObservation,
    /// Runtime observed an effect that Capsec does not require.
    RuntimeObservationWithoutRequirement,
}

impl DifferenceClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequirementWithoutRuntimeAuthority => "requirement-without-runtime-authority",
            Self::RuntimeAuthorityWithoutRequirementOrObservation => {
                "runtime-authority-without-requirement-or-observation"
            }
            Self::RuntimeObservationWithoutRequirement => "runtime-observation-without-requirement",
        }
    }
}

/// Contains one typed comparison result without granting authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DraftDifference {
    class: DifferenceClass,
    subject: String,
    detail: String,
    provenance: BTreeSet<DraftProvenance>,
}

impl DraftDifference {
    /// Creates one bounded comparison result.
    pub fn new(
        class: DifferenceClass,
        subject: impl Into<String>,
        detail: impl Into<String>,
        provenance: impl IntoIterator<Item = DraftProvenance>,
    ) -> Result<Self, DraftError> {
        let subject = subject.into();
        let detail = detail.into();
        let provenance = provenance.into_iter().collect::<BTreeSet<_>>();
        if subject.is_empty()
            || detail.is_empty()
            || subject.len() > 1_048_576
            || detail.len() > 1_048_576
            || provenance.is_empty()
            || provenance.len() > 5
        {
            return Err(DraftError::DifferenceInvalid);
        }
        Ok(Self {
            class,
            subject,
            detail,
            provenance,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "class": self.class.as_str(),
            "detail": self.detail,
            "provenance": self.provenance.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
            "subject": self.subject,
        })
    }
}

/// Identifies one non-authoritative draft candidate kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CandidateKind {
    /// Suggests executable authority for review.
    Execute,
    /// Suggests read authority for review.
    Read,
}

impl CandidateKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Read => "read",
        }
    }
}

/// Contains one bounded, provenance-tagged draft candidate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DraftCandidate {
    kind: CandidateKind,
    path: String,
    provenance: BTreeSet<DraftProvenance>,
}

impl DraftCandidate {
    /// Creates one identified closure candidate. This value does not grant authority.
    pub fn identified_closure(
        kind: CandidateKind,
        path: impl Into<String>,
        provenance: DraftProvenance,
    ) -> Result<Self, DraftError> {
        if !matches!(
            provenance,
            DraftProvenance::PlatformRequiredClosure | DraftProvenance::StaticExecutableClosure
        ) {
            return Err(DraftError::CandidateInvalid);
        }
        Self::new(kind, path, [provenance])
    }

    fn new(
        kind: CandidateKind,
        path: impl Into<String>,
        provenance: impl IntoIterator<Item = DraftProvenance>,
    ) -> Result<Self, DraftError> {
        let path = path.into();
        let provenance = provenance.into_iter().collect::<BTreeSet<_>>();
        validate_absolute_path(&path)?;
        if provenance.is_empty() || provenance.len() > 5 {
            return Err(DraftError::CandidateInvalid);
        }
        Ok(Self {
            kind,
            path,
            provenance,
        })
    }

    fn to_value(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "path": self.path,
            "provenance": self.provenance.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OpenItemCode {
    CapsecAnalyzerUnknown,
    CapsecIncomplete,
    CapsecMissing,
    CapsecReportInvalid,
    CapsecSchemaUnknown,
    CapsecSourceStale,
    ChooseEnvironment,
    ChooseLimits,
    ChooseNetworkMode,
    ChooseWriteRoots,
    DiagnosticGap,
    NetworkAttempt,
    ObservationUnresolved,
}

impl OpenItemCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CapsecAnalyzerUnknown => "capsec-analyzer-unknown",
            Self::CapsecIncomplete => "capsec-incomplete",
            Self::CapsecMissing => "capsec-missing",
            Self::CapsecReportInvalid => "capsec-report-invalid",
            Self::CapsecSchemaUnknown => "capsec-schema-unknown",
            Self::CapsecSourceStale => "capsec-source-stale",
            Self::ChooseEnvironment => "choose-environment",
            Self::ChooseLimits => "choose-limits",
            Self::ChooseNetworkMode => "choose-network-mode",
            Self::ChooseWriteRoots => "choose-write-roots",
            Self::DiagnosticGap => "diagnostic-gap",
            Self::NetworkAttempt => "network-attempt",
            Self::ObservationUnresolved => "observation-unresolved",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OpenItem {
    code: OpenItemCode,
    detail: String,
    provenance: DraftProvenance,
}

impl OpenItem {
    fn new(code: OpenItemCode, detail: impl Into<String>, provenance: DraftProvenance) -> Self {
        Self {
            code,
            detail: detail.into(),
            provenance,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "code": self.code.as_str(),
            "detail": self.detail,
            "provenance": self.provenance.as_str(),
        })
    }
}

/// Contains all optional comparison inputs for draft construction.
#[derive(Default)]
pub struct PlanDraftInputs {
    /// Identifies an optional static scaffold.
    pub static_scaffold: Option<Sha256Digest>,
    /// Retains the exact selected project inputs.
    pub inputs: Vec<DraftInput>,
    /// Retains an optional exact Capsec report tuple.
    pub capsec: Option<CapsecInput>,
    /// Retains typed comparison results.
    pub differences: Vec<DraftDifference>,
    /// Retains non-authoritative candidates from identified external inputs.
    pub candidates: Vec<DraftCandidate>,
    /// Retains exact non-authoritative entries from one identified static closure.
    pub identified_closure: Vec<IdentifiedClosureEntry>,
    /// Restricts automatic candidates to explicit reviewed roots.
    pub path_scope: Option<DraftPathScope>,
}

/// Contains canonical bytes for one reviewable non-policy plan draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDraft {
    bytes: Vec<u8>,
}

impl PlanDraft {
    /// Returns the canonical JSON bytes without a trailing newline.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Builds a conservative plan draft from one constructed diagnostic receipt.
pub fn build_plan_draft(
    receipt: &DiagnosticReceipt,
    mut inputs: PlanDraftInputs,
) -> Result<PlanDraft, DraftError> {
    inputs.inputs.sort();
    inputs.inputs.dedup();
    if inputs.inputs.len() > 65_536 {
        return Err(DraftError::InputInvalid);
    }
    inputs.identified_closure.sort();
    inputs.identified_closure.dedup();
    if inputs.identified_closure.len() > 258 {
        return Err(DraftError::ClosureInvalid);
    }
    inputs.differences.sort();
    if inputs.differences.len() > 1_048_576 {
        return Err(DraftError::DifferenceInvalid);
    }
    inputs.candidates.sort();
    inputs.candidates.dedup();
    if inputs.candidates.len() > 1_048_576 {
        return Err(DraftError::CollectionBoundExceeded);
    }
    if inputs.candidates.iter().any(|candidate| {
        inputs
            .path_scope
            .as_ref()
            .is_none_or(|scope| !scope.allows(&candidate.path))
    }) {
        return Err(DraftError::CandidateInvalid);
    }
    let capsec_unusable = inputs
        .capsec
        .as_ref()
        .is_none_or(|capsec| capsec.usability != CapsecUsability::Usable);
    if capsec_unusable
        && (inputs.differences.iter().any(|difference| {
            difference
                .provenance
                .contains(&DraftProvenance::CapsecSourceObservation)
        }) || inputs.candidates.iter().any(|candidate| {
            candidate
                .provenance
                .contains(&DraftProvenance::CapsecSourceObservation)
        }))
    {
        return Err(DraftError::CapsecProvenanceInvalid);
    }

    let mut candidates = BTreeMap::new();
    for candidate in inputs.candidates {
        merge_candidate(&mut candidates, candidate);
    }
    let mut open_items = mandatory_open_items();
    let mut denial_count = 0_u64;
    let mut unresolved_count = 0_u64;
    let mut broad_root_count = 0_u64;
    for event in receipt.events() {
        if matches!(event.outcome(), ObservationOutcome::Failed(_)) {
            denial_count += 1;
        }
        if event.class().is_network() {
            open_items.insert(OpenItem::new(
                OpenItemCode::NetworkAttempt,
                format!(
                    "Observed {} at event {}; select network authority explicitly.",
                    event.class().as_str(),
                    event.sequence()
                ),
                DraftProvenance::DiagnosticRuntimeObservation,
            ));
        }
        if matches!(
            event.resolution(),
            ObservationResolution::Unresolved | ObservationResolution::Redacted
        ) {
            unresolved_count += 1;
            open_items.insert(OpenItem::new(
                OpenItemCode::ObservationUnresolved,
                format!("Event {} has no exact reusable target.", event.sequence()),
                DraftProvenance::DiagnosticRuntimeObservation,
            ));
            continue;
        }
        let Some(path) = event.resolved_path() else {
            continue;
        };
        if validate_absolute_path(path).is_err() || event.class().is_network() {
            continue;
        }
        if inputs
            .path_scope
            .as_ref()
            .is_none_or(|scope| !scope.allows(path))
        {
            broad_root_count += 1;
            open_items.insert(OpenItem::new(
                OpenItemCode::ObservationUnresolved,
                format!(
                    "Event {} selected a root that is too broad for an automatic suggestion.",
                    event.sequence()
                ),
                DraftProvenance::DiagnosticRuntimeObservation,
            ));
            continue;
        }
        let kind = if event.class().is_execute() {
            Some(CandidateKind::Execute)
        } else if event.class().is_read_candidate() && !path_event_can_write(event) {
            Some(CandidateKind::Read)
        } else {
            None
        };
        if let Some(kind) = kind {
            merge_candidate(
                &mut candidates,
                DraftCandidate {
                    kind,
                    path: path.to_owned(),
                    provenance: BTreeSet::from([DraftProvenance::DiagnosticRuntimeObservation]),
                },
            );
        }
    }
    for gap in receipt.gaps() {
        open_items.insert(OpenItem::new(
            OpenItemCode::DiagnosticGap,
            format!("Diagnostic coverage gap: {}.", gap.as_str()),
            DraftProvenance::DiagnosticRuntimeObservation,
        ));
    }
    add_capsec_open_item(&mut open_items, inputs.capsec.as_ref());
    if candidates.len() > 1_048_576 || open_items.len() > 1_048_576 {
        return Err(DraftError::CollectionBoundExceeded);
    }

    let mut output = BoundedCanonicalJson::new(receipt.output_bound()).map_err(map_write_error)?;
    output.raw(b"{\"arguments\":").map_err(map_write_error)?;
    output.value(receipt.arguments()).map_err(map_write_error)?;
    output.raw(b",\"breadth\":").map_err(map_write_error)?;
    output
        .value(&json!({
            "broad_roots": broad_root_count,
            "denials": denial_count,
            "suggested_roots": candidates.len(),
            "unresolved_events": unresolved_count,
        }))
        .map_err(map_write_error)?;
    output.raw(b",\"candidates\":").map_err(map_write_error)?;
    output
        .sequence(candidates.values().map(DraftCandidate::to_value))
        .map_err(map_write_error)?;
    output.raw(b",\"capsec\":").map_err(map_write_error)?;
    output
        .value(&inputs.capsec.as_ref().map(CapsecInput::to_value))
        .map_err(map_write_error)?;
    output
        .raw(b",\"diagnostic_receipt_commitment\":")
        .map_err(map_write_error)?;
    output
        .value(&format!("sha256:{}", receipt.commitment().to_hex()))
        .map_err(map_write_error)?;
    output.raw(b",\"differences\":").map_err(map_write_error)?;
    output
        .sequence(inputs.differences.iter().map(DraftDifference::to_value))
        .map_err(map_write_error)?;
    output
        .raw(b",\"environment_names\":")
        .map_err(map_write_error)?;
    output
        .value(receipt.environment_names())
        .map_err(map_write_error)?;
    output.raw(b",\"gaps\":").map_err(map_write_error)?;
    output
        .sequence(receipt.gaps().iter().map(|gap| gap.as_str()))
        .map_err(map_write_error)?;
    output
        .raw(b",\"identified_closure\":")
        .map_err(map_write_error)?;
    output
        .sequence(
            inputs
                .identified_closure
                .iter()
                .map(IdentifiedClosureEntry::to_value),
        )
        .map_err(map_write_error)?;
    output.raw(b",\"inputs\":").map_err(map_write_error)?;
    output
        .sequence(inputs.inputs.iter().map(DraftInput::to_value))
        .map_err(map_write_error)?;
    output.raw(b",\"open_items\":").map_err(map_write_error)?;
    output
        .sequence(open_items.iter().map(OpenItem::to_value))
        .map_err(map_write_error)?;
    output
        .raw(b",\"safe_policy\":false,\"schema\":")
        .map_err(map_write_error)?;
    output.value(PLAN_DRAFT_SCHEMA).map_err(map_write_error)?;
    output.raw(b",\"seed_plan\":").map_err(map_write_error)?;
    output
        .value(&format!("sha256:{}", receipt.seed_plan_digest().to_hex()))
        .map_err(map_write_error)?;
    output
        .raw(b",\"static_scaffold\":")
        .map_err(map_write_error)?;
    output
        .value(
            &inputs
                .static_scaffold
                .map(|digest| format!("sha256:{}", digest.to_hex())),
        )
        .map_err(map_write_error)?;
    output.raw(b"}").map_err(map_write_error)?;
    let bytes = output.finish();
    Ok(PlanDraft { bytes })
}

fn map_write_error(error: CanonicalWriteError) -> DraftError {
    match error {
        CanonicalWriteError::BoundExceeded => DraftError::OutputBoundExceeded,
        CanonicalWriteError::EncodingFailed => DraftError::CanonicalEncodingFailed,
    }
}

fn merge_candidate(
    candidates: &mut BTreeMap<(CandidateKind, String), DraftCandidate>,
    candidate: DraftCandidate,
) {
    let key = (candidate.kind, candidate.path.clone());
    if let Some(existing) = candidates.get_mut(&key) {
        existing.provenance.extend(candidate.provenance);
    } else {
        candidates.insert(key, candidate);
    }
}

/// Identifies invalid plan-draft construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DraftError {
    /// One project input is invalid.
    InputInvalid,
    /// The Capsec identity tuple is invalid.
    CapsecInvalid,
    /// Capsec provenance is present without one usable exact input tuple.
    CapsecProvenanceInvalid,
    /// One comparison result is invalid.
    DifferenceInvalid,
    /// One draft candidate is invalid.
    CandidateInvalid,
    /// One identified static closure entry is invalid.
    ClosureInvalid,
    /// A draft collection exceeds the schema bound.
    CollectionBoundExceeded,
    /// Candidate path scope is absent or invalid.
    PathScopeInvalid,
    /// Canonical draft output exceeds the diagnostic output bound.
    OutputBoundExceeded,
    /// Canonical JSON encoding failed.
    CanonicalEncodingFailed,
}

impl DraftError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InputInvalid => "diagnostic.draft.input-invalid",
            Self::CapsecInvalid => "diagnostic.draft.capsec-invalid",
            Self::CapsecProvenanceInvalid => "diagnostic.draft.capsec-provenance-invalid",
            Self::DifferenceInvalid => "diagnostic.draft.difference-invalid",
            Self::CandidateInvalid => "diagnostic.draft.candidate-invalid",
            Self::ClosureInvalid => "diagnostic.draft.closure-invalid",
            Self::CollectionBoundExceeded => "diagnostic.draft.collection-bound-exceeded",
            Self::PathScopeInvalid => "diagnostic.draft.path-scope-invalid",
            Self::OutputBoundExceeded => "diagnostic.draft.output-bound-exceeded",
            Self::CanonicalEncodingFailed => "diagnostic.draft.canonical-json-failed",
        }
    }
}

impl fmt::Display for DraftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DraftError {}

fn mandatory_open_items() -> BTreeSet<OpenItem> {
    BTreeSet::from([
        OpenItem::new(
            OpenItemCode::ChooseEnvironment,
            "Select registered environment names.",
            DraftProvenance::HumanAuthored,
        ),
        OpenItem::new(
            OpenItemCode::ChooseLimits,
            "Select every resource limit.",
            DraftProvenance::HumanAuthored,
        ),
        OpenItem::new(
            OpenItemCode::ChooseNetworkMode,
            "Select the network mode.",
            DraftProvenance::HumanAuthored,
        ),
        OpenItem::new(
            OpenItemCode::ChooseWriteRoots,
            "Select write roots.",
            DraftProvenance::HumanAuthored,
        ),
    ])
}

fn add_capsec_open_item(open_items: &mut BTreeSet<OpenItem>, capsec: Option<&CapsecInput>) {
    let (code, detail, provenance) = match capsec.map(|value| value.usability) {
        None => (
            OpenItemCode::CapsecMissing,
            "No Capsec report was selected.",
            DraftProvenance::HumanAuthored,
        ),
        Some(CapsecUsability::AnalyzerUnknown) => (
            OpenItemCode::CapsecAnalyzerUnknown,
            "The Capsec analyzer identity is not accepted.",
            DraftProvenance::CapsecSourceObservation,
        ),
        Some(CapsecUsability::Incomplete) => (
            OpenItemCode::CapsecIncomplete,
            "The Capsec report declares incomplete coverage.",
            DraftProvenance::CapsecSourceObservation,
        ),
        Some(CapsecUsability::ReportInvalid) => (
            OpenItemCode::CapsecReportInvalid,
            "The Capsec report is invalid.",
            DraftProvenance::CapsecSourceObservation,
        ),
        Some(CapsecUsability::SchemaUnknown) => (
            OpenItemCode::CapsecSchemaUnknown,
            "The Capsec schema identity is not accepted.",
            DraftProvenance::CapsecSourceObservation,
        ),
        Some(CapsecUsability::SourceStale) => (
            OpenItemCode::CapsecSourceStale,
            "The Capsec report identifies different source bytes.",
            DraftProvenance::CapsecSourceObservation,
        ),
        Some(CapsecUsability::Usable) => return,
    };
    open_items.insert(OpenItem::new(code, detail, provenance));
}

fn path_event_can_write(event: &DiagnosticEvent) -> bool {
    if event.class() == DiagnosticEventClass::Creat {
        return true;
    }
    event
        .operands()
        .path_flags()
        .is_none_or(|flags| flags & 0b11 != 0 || flags & 0o100 != 0 || flags & 0o1000 != 0)
}

fn validate_absolute_path(path: &str) -> Result<(), DraftError> {
    if !is_normalized_absolute_path(path) || path.len() > 1_048_576 {
        return Err(DraftError::InputInvalid);
    }
    Ok(())
}

fn canonical_path_set(
    paths: impl IntoIterator<Item = String>,
    allow_root: bool,
) -> Result<BTreeSet<String>, DraftError> {
    let paths = paths.into_iter().collect::<BTreeSet<_>>();
    if paths.len() > 256
        || paths
            .iter()
            .any(|path| validate_absolute_path(path).is_err() || (!allow_root && path == "/"))
    {
        return Err(DraftError::PathScopeInvalid);
    }
    Ok(paths)
}

fn path_is_within(path: &str, root: &str) -> bool {
    path == root
        || root == "/"
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_system_path(path: &str) -> bool {
    [
        "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
        "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
    ]
    .into_iter()
    .any(|root| path_is_within(path, root))
}

fn valid_schema_identity(value: &str) -> bool {
    let Some((name, version)) = value.rsplit_once('/') else {
        return false;
    };
    !name.is_empty()
        && value.len() <= 256
        && name.as_bytes().iter().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
        && !version.is_empty()
        && version.as_bytes()[0] != b'0'
        && version.as_bytes().iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::tests::fixture_receipt;
    use crate::artifact::{
        DiagnosticArtifactIdentity, DiagnosticArtifactRole, DiagnosticEvent, DiagnosticPlatform,
        DiagnosticReceiptParts, DiagnosticTcbEntry, DiagnosticTcbRole, ObservationBounds,
        ObservationOperands, ObservedObjectIdentity,
    };
    use proofbound_runtime_core::{Architecture, DiagnosticCompletion, ExecutionId, FileMode};

    fn fixture_scope() -> DraftPathScope {
        DraftPathScope::new(
            ["/workspace".to_owned()],
            "/workspace/user-home".to_owned(),
            ["/workspace/.tmp".to_owned()],
        )
        .expect("fixture path scope")
    }

    #[test]
    fn broad_roots_are_excluded_from_automatic_candidates() {
        let object =
            ObservedObjectIdentity::new(8, 1, 42, 0o040755, 7).expect("fixture root identity");
        let event = DiagnosticEvent::new(
            0,
            1000,
            Architecture::X86_64,
            DiagnosticEventClass::Open,
            ObservationOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: Some(0),
                mask: None,
                mode: None,
                path: Some("/".to_owned()),
                resolve: None,
                symlink_hops: Some(0),
            },
            ObservationOutcome::Failed(13),
            ObservationResolution::StableCandidate,
            Some("/".to_owned()),
            Some(object.clone()),
            Some(object),
        )
        .expect("fixture root event");
        let artifact = |role, byte, size, mode| {
            DiagnosticArtifactIdentity::new(
                role,
                Sha256Digest::from_bytes([byte; 32]),
                size,
                FileMode::new(mode).expect("fixture mode"),
            )
            .expect("fixture artifact")
        };
        let receipt = crate::artifact::DiagnosticReceipt::construct(DiagnosticReceiptParts {
            execution_id: ExecutionId::from_bytes([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
            .expect("fixture execution identifier"),
            seed_plan: artifact(DiagnosticArtifactRole::ExecutionPlan, 0x44, 4, 0o644),
            target: artifact(DiagnosticArtifactRole::RuntimeExecutable, 0x55, 5, 0o755),
            runtime: artifact(DiagnosticArtifactRole::RuntimeBinary, 0x11, 1, 0o755),
            launcher: artifact(DiagnosticArtifactRole::LauncherBinary, 0x22, 2, 0o755),
            observer: artifact(DiagnosticArtifactRole::DiagnosticObserver, 0x33, 3, 0o755),
            platform: DiagnosticPlatform::new(Architecture::X86_64, "fixture", 11)
                .expect("fixture platform"),
            arguments: vec!["--fixture".to_owned()],
            environment_names: vec![],
            bounds: ObservationBounds {
                event_count: 8,
                event_count_per_process: 8,
                output_bytes: 1_048_576,
                path_bytes: 4096,
                process_count: 2,
                socket_address_bytes: 128,
                symlink_hops: 40,
                tracee_string_bytes: 4096,
            },
            events: vec![event],
            completion: DiagnosticCompletion::Complete,
            gaps: vec![],
            trusted_computing_base: [
                (DiagnosticTcbRole::DiagnosticObserver, "fixture-observer"),
                (DiagnosticTcbRole::Filesystem, "fixture-filesystem"),
                (DiagnosticTcbRole::Hardware, "fixture-hardware"),
                (DiagnosticTcbRole::LinuxKernel, "fixture-kernel"),
                (DiagnosticTcbRole::RuntimeLauncher, "fixture-launcher"),
                (DiagnosticTcbRole::RuntimeSupervisor, "fixture-supervisor"),
            ]
            .into_iter()
            .map(|(role, identity)| {
                DiagnosticTcbEntry::new(role, identity).expect("fixture trusted role")
            })
            .collect(),
            assumptions: vec!["PBR-HOST-AX-002".to_owned()],
        })
        .expect("fixture receipt");
        let draft = build_plan_draft(&receipt, PlanDraftInputs::default()).expect("fixture draft");
        let value: Value = serde_json::from_slice(draft.as_bytes()).expect("draft JSON");
        assert_eq!(value["candidates"], json!([]));
        assert_eq!(value["breadth"]["broad_roots"], 1);
        assert!(
            value["open_items"]
                .as_array()
                .expect("open items")
                .iter()
                .any(|item| item["code"] == "observation-unresolved")
        );
        assert_eq!(
            DraftPathScope::new(
                ["/workspace/../etc".to_owned()],
                "/workspace/user-home".to_owned(),
                Vec::new(),
            ),
            Err(DraftError::PathScopeInvalid)
        );
    }

    #[test]
    fn path_scope_excludes_nested_system_home_and_temporary_roots() {
        for candidate in [
            "/usr/local/project",
            "/workspace/user-home/project",
            "/workspace/.tmp/project",
        ] {
            assert_eq!(
                DraftPathScope::new(
                    [candidate.to_owned()],
                    "/workspace/user-home".to_owned(),
                    ["/workspace/.tmp".to_owned()],
                ),
                Err(DraftError::PathScopeInvalid)
            );
        }
        let scope = fixture_scope();
        assert!(!scope.allows("/usr/local/lib/runtime.so"));
        assert!(!scope.allows("/workspace/user-home/.ssh/config"));
        assert!(!scope.allows("/workspace/.tmp/cache"));
        assert!(scope.allows("/workspace/project/config"));
    }

    #[test]
    fn draft_keeps_authority_choices_open() {
        let draft = build_plan_draft(&fixture_receipt(), PlanDraftInputs::default())
            .expect("fixture draft");
        let value: Value = serde_json::from_slice(draft.as_bytes()).expect("draft JSON");
        assert_eq!(value["safe_policy"], false);
        let codes = value["open_items"]
            .as_array()
            .expect("open items")
            .iter()
            .map(|item| item["code"].as_str().expect("open-item code"))
            .collect::<BTreeSet<_>>();
        assert!(
            [
                "choose-environment",
                "choose-limits",
                "choose-network-mode",
                "choose-write-roots",
            ]
            .into_iter()
            .all(|code| codes.contains(code))
        );
        assert!(!value.to_string().contains("write-roots\":["));
        assert!(!value.to_string().contains("network-authority"));
    }

    #[test]
    fn draft_preserves_provenance_and_network_non_grant() {
        let draft = build_plan_draft(
            &fixture_receipt(),
            PlanDraftInputs {
                path_scope: Some(fixture_scope()),
                ..PlanDraftInputs::default()
            },
        )
        .expect("fixture draft");
        assert_eq!(
            draft.as_bytes(),
            include_bytes!("../../../schemas/vectors/diagnostic/plan-draft.json")
                .strip_suffix(b"\n")
                .unwrap_or(include_bytes!(
                    "../../../schemas/vectors/diagnostic/plan-draft.json"
                ))
        );
        let value: Value = serde_json::from_slice(draft.as_bytes()).expect("draft JSON");
        assert_eq!(
            value["candidates"],
            json!([{
                "kind": "read",
                "path": "/workspace/config",
                "provenance": ["diagnostic-runtime-observation"],
            }])
        );
        let codes = value["open_items"]
            .as_array()
            .expect("open items")
            .iter()
            .map(|item| item["code"].as_str().expect("open-item code"))
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("network-attempt"));
        assert!(codes.contains("observation-unresolved"));
        assert!(codes.contains("diagnostic-gap"));
        assert!(codes.contains("capsec-missing"));
        assert_eq!(value["breadth"]["denials"], 2);
        assert_eq!(value["breadth"]["suggested_roots"], 1);
        assert_eq!(value["breadth"]["unresolved_events"], 1);
        assert_eq!(value["gaps"], json!(["event-limit"]));

        let executable = IdentifiedClosureEntry::new(
            IdentifiedClosureRole::Executable,
            "/workspace/tool",
            ContentIdentity::new(Sha256Digest::from_bytes([7; 32]), 7),
            0o755,
            DraftProvenance::StaticExecutableClosure,
        )
        .expect("identified executable");
        let library = IdentifiedClosureEntry::new(
            IdentifiedClosureRole::RuntimeLibrary,
            "/lib/libfixture.so",
            ContentIdentity::new(Sha256Digest::from_bytes([8; 32]), 8),
            0o644,
            DraftProvenance::PlatformRequiredClosure,
        )
        .expect("identified library");
        let identified = build_plan_draft(
            &fixture_receipt(),
            PlanDraftInputs {
                identified_closure: vec![library, executable],
                path_scope: Some(fixture_scope()),
                ..PlanDraftInputs::default()
            },
        )
        .expect("draft");
        let identified: Value = serde_json::from_slice(identified.as_bytes()).expect("draft JSON");
        assert_eq!(
            identified["identified_closure"],
            json!([
                {
                    "mode": "0755",
                    "path": "/workspace/tool",
                    "provenance": "static-executable-closure",
                    "role": "executable",
                    "sha256": format!("sha256:{}", "07".repeat(32)),
                    "size_bytes": 7,
                },
                {
                    "mode": "0644",
                    "path": "/lib/libfixture.so",
                    "provenance": "platform-required-closure",
                    "role": "runtime-library",
                    "sha256": format!("sha256:{}", "08".repeat(32)),
                    "size_bytes": 8,
                },
            ])
        );
        assert_eq!(identified["safe_policy"], false);
    }

    #[test]
    fn capsec_usability_is_derived_from_exact_identities() {
        let expected_source = ContentIdentity::new(Sha256Digest::from_bytes([1; 32]), 10);
        let expected_analyzer = ContentIdentity::new(Sha256Digest::from_bytes([2; 32]), 20);
        let expected_report = ContentIdentity::new(Sha256Digest::from_bytes([3; 32]), 30);
        let profile = CapsecIntegrationProfile::new(
            "capsec-report/1",
            expected_source,
            expected_analyzer,
            expected_report,
        )
        .expect("Capsec profile");
        let stale = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "capsec-report/1",
                ContentIdentity::new(Sha256Digest::from_bytes([4; 32]), 10),
                expected_analyzer,
                expected_report,
                true,
                true,
            )
            .expect("stale observation"),
        );
        assert_eq!(stale.usability(), CapsecUsability::SourceStale);
        assert_eq!(
            IdentifiedClosureEntry::new(
                IdentifiedClosureRole::RuntimeLibrary,
                "/lib/libfixture.so",
                ContentIdentity::new(Sha256Digest::from_bytes([8; 32]), 8),
                0o644,
                DraftProvenance::CapsecSourceObservation,
            ),
            Err(DraftError::ClosureInvalid)
        );
        let wrong_report = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "capsec-report/1",
                expected_source,
                expected_analyzer,
                ContentIdentity::new(Sha256Digest::from_bytes([9; 32]), 30),
                true,
                true,
            )
            .expect("wrong-report observation"),
        );
        assert_eq!(wrong_report.usability(), CapsecUsability::ReportInvalid);
        let wrong_schema = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "other-report/1",
                expected_source,
                expected_analyzer,
                expected_report,
                true,
                true,
            )
            .expect("wrong-schema observation"),
        );
        assert_eq!(wrong_schema.usability(), CapsecUsability::SchemaUnknown);
        let wrong_analyzer = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "capsec-report/1",
                expected_source,
                ContentIdentity::new(Sha256Digest::from_bytes([8; 32]), 20),
                expected_report,
                true,
                true,
            )
            .expect("wrong-analyzer observation"),
        );
        assert_eq!(wrong_analyzer.usability(), CapsecUsability::AnalyzerUnknown);
        let incomplete = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "capsec-report/1",
                expected_source,
                expected_analyzer,
                expected_report,
                true,
                false,
            )
            .expect("incomplete observation"),
        );
        assert_eq!(incomplete.usability(), CapsecUsability::Incomplete);
        let usable = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "capsec-report/1",
                expected_source,
                expected_analyzer,
                expected_report,
                true,
                true,
            )
            .expect("usable observation"),
        );
        assert_eq!(usable.usability(), CapsecUsability::Usable);
        let difference = DraftDifference::new(
            DifferenceClass::RuntimeObservationWithoutRequirement,
            "/workspace/config",
            "The runtime observation has no matching source requirement.",
            [DraftProvenance::CapsecSourceObservation],
        )
        .expect("fixture difference");
        assert_eq!(
            build_plan_draft(
                &fixture_receipt(),
                PlanDraftInputs {
                    capsec: Some(stale.clone()),
                    differences: vec![difference],
                    ..PlanDraftInputs::default()
                }
            ),
            Err(DraftError::CapsecProvenanceInvalid)
        );
        let relabeled_candidate = DraftCandidate::new(
            CandidateKind::Read,
            "/workspace/config",
            [DraftProvenance::CapsecSourceObservation],
        )
        .expect("candidate");
        assert_eq!(
            build_plan_draft(
                &fixture_receipt(),
                PlanDraftInputs {
                    capsec: Some(stale),
                    candidates: vec![relabeled_candidate],
                    path_scope: Some(fixture_scope()),
                    ..PlanDraftInputs::default()
                }
            ),
            Err(DraftError::CapsecProvenanceInvalid)
        );
    }

    #[test]
    fn draft_output_is_bounded_by_the_diagnostic_receipt() {
        let difference = DraftDifference::new(
            DifferenceClass::RuntimeObservationWithoutRequirement,
            "/workspace/config",
            "x".repeat(1_048_576),
            [DraftProvenance::DiagnosticRuntimeObservation],
        )
        .expect("maximum-size difference");
        assert_eq!(
            build_plan_draft(
                &fixture_receipt(),
                PlanDraftInputs {
                    differences: vec![difference],
                    path_scope: Some(fixture_scope()),
                    ..PlanDraftInputs::default()
                },
            ),
            Err(DraftError::OutputBoundExceeded)
        );
    }
}
