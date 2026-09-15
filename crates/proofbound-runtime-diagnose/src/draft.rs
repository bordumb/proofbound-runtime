//! Constructs a reviewable plan draft from one diagnostic receipt.

use core::fmt;
use std::collections::BTreeSet;

use proofbound_runtime_core::{DraftProvenance, ObservationResolution, Sha256Digest};
use serde_json::{Value, json};

use crate::artifact::{
    DiagnosticEvent, DiagnosticEventClass, DiagnosticGap, DiagnosticReceipt, ObservationOutcome,
};

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
        validate_absolute_path(&path)?;
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
}

impl CapsecIntegrationProfile {
    /// Creates one exact accepted Capsec tuple.
    pub fn new(
        schema_identity: impl Into<String>,
        source: ContentIdentity,
        analyzer: ContentIdentity,
    ) -> Result<Self, DraftError> {
        let schema_identity = schema_identity.into();
        if !valid_schema_identity(&schema_identity) {
            return Err(DraftError::CapsecInvalid);
        }
        Ok(Self {
            schema_identity,
            source,
            analyzer,
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
        } else if !observation.structurally_valid {
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
            || subject.as_bytes().len() > 1_048_576
            || detail.as_bytes().len() > 1_048_576
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CandidateKind {
    Execute,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DraftCandidate {
    kind: CandidateKind,
    path: String,
    provenance: BTreeSet<DraftProvenance>,
}

impl DraftCandidate {
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
    inputs.differences.sort();
    if inputs.differences.len() > 1_048_576 {
        return Err(DraftError::DifferenceInvalid);
    }
    if inputs.differences.iter().any(|difference| {
        difference
            .provenance
            .contains(&DraftProvenance::CapsecSourceObservation)
            && inputs
                .capsec
                .as_ref()
                .is_none_or(|capsec| capsec.usability != CapsecUsability::Usable)
    }) {
        return Err(DraftError::CapsecProvenanceInvalid);
    }

    let mut candidates = BTreeSet::new();
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
        if is_broad_root(path) {
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
            candidates.insert(DraftCandidate {
                kind,
                path: path.to_owned(),
                provenance: BTreeSet::from([DraftProvenance::DiagnosticRuntimeObservation]),
            });
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

    let candidates = candidates
        .iter()
        .map(DraftCandidate::to_value)
        .collect::<Vec<_>>();
    let open_items = open_items
        .iter()
        .map(OpenItem::to_value)
        .collect::<Vec<_>>();
    let gaps = receipt
        .gaps()
        .iter()
        .map(|gap| gap.as_str())
        .collect::<Vec<_>>();
    let value = json!({
        "arguments": receipt.arguments(),
        "breadth": {
            "broad_roots": broad_root_count,
            "denials": denial_count,
            "suggested_roots": candidates.len(),
            "unresolved_events": unresolved_count,
        },
        "candidates": candidates,
        "capsec": inputs.capsec.as_ref().map(CapsecInput::to_value),
        "diagnostic_receipt_commitment": format!("sha256:{}", receipt.commitment().to_hex()),
        "differences": inputs.differences.iter().map(DraftDifference::to_value).collect::<Vec<_>>(),
        "environment_names": receipt.environment_names(),
        "gaps": gaps,
        "inputs": inputs.inputs.iter().map(DraftInput::to_value).collect::<Vec<_>>(),
        "open_items": open_items,
        "safe_policy": false,
        "schema": PLAN_DRAFT_SCHEMA,
        "seed_plan": format!("sha256:{}", receipt.seed_plan_digest().to_hex()),
        "static_scaffold": inputs.static_scaffold.map(|digest| format!("sha256:{}", digest.to_hex())),
    });
    let bytes = serde_json::to_vec(&value).map_err(|_| DraftError::CanonicalEncodingFailed)?;
    Ok(PlanDraft { bytes })
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
    /// A draft collection exceeds the schema bound.
    CollectionBoundExceeded,
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
            Self::CollectionBoundExceeded => "diagnostic.draft.collection-bound-exceeded",
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
    if !path.starts_with('/') || path.as_bytes().contains(&0) || path.as_bytes().len() > 1_048_576 {
        return Err(DraftError::InputInvalid);
    }
    Ok(())
}

fn is_broad_root(path: &str) -> bool {
    matches!(
        path,
        "/" | "/bin"
            | "/etc"
            | "/home"
            | "/lib"
            | "/lib64"
            | "/opt"
            | "/root"
            | "/sbin"
            | "/tmp"
            | "/usr"
            | "/var"
            | "/var/tmp"
    )
}

fn valid_schema_identity(value: &str) -> bool {
    let Some((name, version)) = value.rsplit_once('/') else {
        return false;
    };
    !name.is_empty()
        && value.as_bytes().len() <= 256
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
        Architecture, DiagnosticArtifactIdentity, DiagnosticArtifactRole, DiagnosticCompletion,
        DiagnosticEvent, DiagnosticPlatform, DiagnosticReceiptParts, DiagnosticTcbEntry,
        DiagnosticTcbRole, FileMode, ObservationBounds, ObservationOperands,
        ObservedObjectIdentity,
    };

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
            },
            ObservationOutcome::Returned(3),
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
            execution_id: proofbound_runtime_core::ExecutionId::from_bytes([0x42; 16])
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
                process_count: 1,
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
        let draft = build_plan_draft(&fixture_receipt(), PlanDraftInputs::default())
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
    }

    #[test]
    fn capsec_usability_is_derived_from_exact_identities() {
        let expected_source = ContentIdentity::new(Sha256Digest::from_bytes([1; 32]), 10);
        let expected_analyzer = ContentIdentity::new(Sha256Digest::from_bytes([2; 32]), 20);
        let report = ContentIdentity::new(Sha256Digest::from_bytes([3; 32]), 30);
        let profile =
            CapsecIntegrationProfile::new("capsec-report/1", expected_source, expected_analyzer)
                .expect("Capsec profile");
        let stale = CapsecInput::evaluate(
            &profile,
            CapsecReportObservation::new(
                "capsec-report/1",
                ContentIdentity::new(Sha256Digest::from_bytes([4; 32]), 10),
                expected_analyzer,
                report,
                true,
                true,
            )
            .expect("stale observation"),
        );
        assert_eq!(stale.usability(), CapsecUsability::SourceStale);
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
                    capsec: Some(stale),
                    differences: vec![difference],
                    ..PlanDraftInputs::default()
                }
            ),
            Err(DraftError::CapsecProvenanceInvalid)
        );
    }
}
