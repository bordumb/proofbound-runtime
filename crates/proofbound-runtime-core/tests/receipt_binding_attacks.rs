use proofbound_runtime_core::{
    Architecture, ArtifactIdentity, ArtifactRole, BoundaryInstallation, BoundaryRecord,
    CgroupIdentity, EnvironmentName, ExecutionId, ExecutionObservations, ExecutionOutcome,
    ExecutionReceipt, ExecutionReceiptParts, FileMode, NonReusableReason,
    REQUIRED_RUNTIME_ASSUMPTIONS, ReceiptCommand, ReceiptEligibility, ReceiptError, ReceiptPlan,
    ReceiptPolicy, ReceiptStreams, RuntimeIdentity, Sha256Digest, StreamCapture,
    TrustedComputingBaseEntry, TrustedComputingBaseRole,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttackCatalog {
    schema: String,
    cases: Vec<AttackCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttackCase {
    id: String,
    mutation: String,
    expected_error: Option<String>,
    expected_reason: Option<String>,
}

fn catalog() -> AttackCatalog {
    toml::from_str(include_str!(
        "../../../tests/attacks/receipt/construction-v1.toml"
    ))
    .expect("receipt construction attack catalog is valid")
}

fn expected_error(id: &str) -> String {
    let catalog = catalog();
    catalog
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .and_then(|case| case.expected_error)
        .expect("attack has an expected error")
}

fn expected_reason(id: &str) -> String {
    let catalog = catalog();
    catalog
        .cases
        .into_iter()
        .find(|case| case.id == id)
        .and_then(|case| case.expected_reason)
        .expect("attack has an expected reason")
}

fn artifact(role: ArtifactRole, marker: u8) -> ArtifactIdentity {
    ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes([marker; 32]),
        u64::from(marker),
        FileMode::new(0o640).expect("fixture mode is valid"),
    )
}

fn execution_id(marker: u8) -> ExecutionId {
    let mut bytes = [marker; 16];
    bytes[6] = 0x40 | (marker & 0x0f);
    bytes[8] = 0x80 | (marker & 0x3f);
    ExecutionId::from_bytes(bytes).expect("fixture is an RFC 4122 version 4 identifier")
}

fn required_tcb() -> Vec<TrustedComputingBaseEntry> {
    [
        TrustedComputingBaseRole::HostHardwareFirmware,
        TrustedComputingBaseRole::LinuxKernel,
        TrustedComputingBaseRole::Landlock,
        TrustedComputingBaseRole::Seccomp,
        TrustedComputingBaseRole::CgroupV2,
        TrustedComputingBaseRole::NoNewPrivileges,
        TrustedComputingBaseRole::Filesystem,
        TrustedComputingBaseRole::RuntimeBinary,
        TrustedComputingBaseRole::LauncherBinary,
        TrustedComputingBaseRole::RustToolchain,
        TrustedComputingBaseRole::CryptographicDigest,
        TrustedComputingBaseRole::RuntimeExecutable,
        TrustedComputingBaseRole::RuntimeLoaderExecutable,
        TrustedComputingBaseRole::RuntimeLibrary,
    ]
    .into_iter()
    .map(|role| {
        TrustedComputingBaseEntry::new(role, format!("{}:fixture", role.as_str()))
            .expect("fixture TCB entry is valid")
    })
    .collect()
}

fn parts() -> ExecutionReceiptParts {
    let execution_id = execution_id(1);
    let policy = artifact(ArtifactRole::CompiledPolicy, 3);
    let runtime = artifact(ArtifactRole::RuntimeBinary, 4);
    ExecutionReceiptParts {
        execution_id,
        plan: ReceiptPlan::new(
            proofbound_runtime_core::PlanId::new("attack.plan").expect("fixture plan id is valid"),
            artifact(ArtifactRole::ExecutionPlan, 1),
            artifact(ArtifactRole::NormalizedPlan, 2),
        )
        .expect("fixture plan roles are valid"),
        policy: ReceiptPolicy::new(policy.clone()).expect("fixture policy role is valid"),
        platform: proofbound_runtime_core::PlatformIdentity::new(
            Architecture::X86_64,
            "6.12.0",
            6,
            vec!["tsync".to_owned()],
            vec!["pids".to_owned()],
        )
        .expect("fixture platform is valid"),
        runtime: RuntimeIdentity::new(runtime.clone(), artifact(ArtifactRole::LauncherBinary, 5))
            .expect("fixture runtime roles are valid"),
        command: ReceiptCommand::new(
            artifact(ArtifactRole::RuntimeExecutable, 6),
            Some(artifact(ArtifactRole::RuntimeLoaderExecutable, 7)),
            artifact(ArtifactRole::WorkingDirectory, 8),
            Sha256Digest::from_bytes([9; 32]),
        )
        .expect("fixture command roles are valid"),
        inputs: vec![
            artifact(ArtifactRole::ProjectInput, 11),
            artifact(ArtifactRole::RuntimeLibrary, 10),
        ],
        environment: vec![EnvironmentName::new("PATH").expect("fixture name is valid")],
        output_root: artifact(ArtifactRole::OutputRoot, 12),
        boundary: BoundaryRecord::new(
            BoundaryInstallation::Installed,
            execution_id,
            policy.digest(),
            CgroupIdentity::new(13, 14),
        ),
        observations: ExecutionObservations::new(15, 16)
            .expect("fixture observation order is valid"),
        streams: ReceiptStreams::new(
            artifact(ArtifactRole::StandardOutput, 17),
            StreamCapture::Complete,
            artifact(ArtifactRole::StandardError, 18),
            StreamCapture::Complete,
        )
        .expect("fixture stream roles are valid"),
        outcome: ExecutionOutcome::Exited { code: 0 },
        resources: None,
        outputs: vec![artifact(ArtifactRole::OutputArtifact, 19)],
        producer: runtime,
        assumptions: REQUIRED_RUNTIME_ASSUMPTIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        trusted_computing_base: required_tcb(),
    }
}

#[test]
fn frozen_constructor_attack_catalog_is_closed() {
    let catalog = catalog();
    assert_eq!(
        catalog.schema,
        "proofbound-runtime-receipt-construction-attacks/1"
    );
    assert_eq!(catalog.cases.len(), 8);
    for case in catalog.cases {
        assert!(!case.id.is_empty());
        assert!(!case.mutation.is_empty());
        assert_ne!(
            case.expected_error.is_some(),
            case.expected_reason.is_some()
        );
    }
}

#[test]
fn constructor_rejects_wrong_required_roles() {
    let expected = expected_error("wrong-required-role");
    let wrong = || artifact(ArtifactRole::ProjectInput, 99);
    let plan_id =
        proofbound_runtime_core::PlanId::new("wrong-role.plan").expect("fixture plan id is valid");
    let cases = [
        ReceiptPlan::new(
            plan_id.clone(),
            wrong(),
            artifact(ArtifactRole::NormalizedPlan, 2),
        )
        .expect_err("wrong source-plan role must fail"),
        ReceiptPlan::new(plan_id, artifact(ArtifactRole::ExecutionPlan, 1), wrong())
            .expect_err("wrong normalized-plan role must fail"),
        ReceiptPolicy::new(wrong()).expect_err("wrong policy role must fail"),
        RuntimeIdentity::new(wrong(), artifact(ArtifactRole::LauncherBinary, 5))
            .expect_err("wrong runtime role must fail"),
        RuntimeIdentity::new(artifact(ArtifactRole::RuntimeBinary, 4), wrong())
            .expect_err("wrong launcher role must fail"),
        ReceiptCommand::new(
            wrong(),
            None,
            artifact(ArtifactRole::WorkingDirectory, 8),
            Sha256Digest::from_bytes([9; 32]),
        )
        .expect_err("wrong executable role must fail"),
        ReceiptCommand::new(
            artifact(ArtifactRole::RuntimeExecutable, 6),
            Some(wrong()),
            artifact(ArtifactRole::WorkingDirectory, 8),
            Sha256Digest::from_bytes([9; 32]),
        )
        .expect_err("wrong loader role must fail"),
        ReceiptCommand::new(
            artifact(ArtifactRole::RuntimeExecutable, 6),
            None,
            wrong(),
            Sha256Digest::from_bytes([9; 32]),
        )
        .expect_err("wrong working-directory role must fail"),
        ReceiptStreams::new(
            wrong(),
            StreamCapture::Complete,
            artifact(ArtifactRole::StandardError, 18),
            StreamCapture::Complete,
        )
        .expect_err("wrong stdout role must fail"),
        ReceiptStreams::new(
            artifact(ArtifactRole::StandardOutput, 17),
            StreamCapture::Complete,
            wrong(),
            StreamCapture::Complete,
        )
        .expect_err("wrong stderr role must fail"),
    ];
    for error in cases {
        assert!(matches!(error, ReceiptError::RoleMismatch(_)));
        assert_eq!(error.code(), expected);
    }

    for mutation in ["input", "output-root", "output", "producer"] {
        let mut input = parts();
        match mutation {
            "input" => input.inputs = vec![artifact(ArtifactRole::RuntimeBinary, 99)],
            "output-root" => input.output_root = wrong(),
            "output" => input.outputs = vec![wrong()],
            "producer" => input.producer = wrong(),
            _ => unreachable!(),
        }
        assert_eq!(
            ExecutionReceipt::new(input)
                .expect_err("wrong top-level artifact role must fail")
                .code(),
            expected
        );
    }
}

#[test]
fn constructor_rejects_replay_and_identity_substitution() {
    let mut replay = parts();
    replay.boundary = BoundaryRecord::new(
        BoundaryInstallation::Installed,
        execution_id(2),
        Sha256Digest::from_bytes([3; 32]),
        CgroupIdentity::new(13, 14),
    );
    assert_eq!(
        ExecutionReceipt::new(replay)
            .expect_err("replay must fail")
            .code(),
        expected_error("execution-replay")
    );

    let mut policy_substitution = parts();
    policy_substitution.boundary = BoundaryRecord::new(
        BoundaryInstallation::Installed,
        execution_id(1),
        Sha256Digest::from_bytes([99; 32]),
        CgroupIdentity::new(13, 14),
    );
    assert_eq!(
        ExecutionReceipt::new(policy_substitution)
            .expect_err("policy substitution must fail")
            .code(),
        expected_error("policy-substitution")
    );

    let mut producer_substitution = parts();
    producer_substitution.producer = artifact(ArtifactRole::RuntimeBinary, 99);
    assert_eq!(
        ExecutionReceipt::new(producer_substitution)
            .expect_err("producer substitution must fail")
            .code(),
        expected_error("producer-substitution")
    );
}

#[test]
fn constructor_rejects_duplicate_artifacts_and_premise_loss() {
    let mut duplicate = parts();
    duplicate.inputs.push(duplicate.inputs[0].clone());
    assert_eq!(
        ExecutionReceipt::new(duplicate)
            .expect_err("duplicate input must fail")
            .code(),
        expected_error("duplicate-input")
    );

    let mut missing_assumption = parts();
    missing_assumption
        .assumptions
        .retain(|value| value != "PBR-HOST-AX-002");
    assert_eq!(
        ExecutionReceipt::new(missing_assumption)
            .expect_err("assumption loss must fail")
            .code(),
        expected_error("remove-assumption")
    );

    let mut missing_tcb_role = parts();
    missing_tcb_role.trusted_computing_base = required_tcb()
        .into_iter()
        .filter(|entry| entry.role() != TrustedComputingBaseRole::Seccomp)
        .collect();
    assert_eq!(
        ExecutionReceipt::new(missing_tcb_role)
            .expect_err("TCB role loss must fail")
            .code(),
        expected_error("remove-tcb-role")
    );
}

#[test]
fn truncation_is_retained_as_nonreuse_evidence() {
    let mut truncated = parts();
    truncated.streams = ReceiptStreams::new(
        artifact(ArtifactRole::StandardOutput, 17),
        StreamCapture::Truncated,
        artifact(ArtifactRole::StandardError, 18),
        StreamCapture::Complete,
    )
    .expect("fixture stream roles are valid");
    let receipt = ExecutionReceipt::new(truncated).expect("truncation is representable");
    let ReceiptEligibility::NonReusable(reasons) = receipt.eligibility() else {
        panic!("truncated output must make the receipt non-reusable");
    };
    assert_eq!(
        reasons.as_slice(),
        [NonReusableReason::StandardOutputTruncated]
    );
    assert_eq!(expected_reason("truncate-stdout"), "stdout-truncated");
}

#[test]
fn canonical_receipt_retains_every_required_top_level_field() {
    let receipt = ExecutionReceipt::new(parts()).expect("fixture receipt is valid");
    let bytes = receipt.canonical_bytes().expect("fixture receipt encodes");
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("receipt JSON decodes");
    let object = value.as_object().expect("receipt is an object");
    let required = [
        "assumptions",
        "boundary",
        "command",
        "eligibility",
        "environment",
        "execution_id",
        "inputs",
        "observations",
        "outcome",
        "output_root",
        "outputs",
        "plan",
        "platform",
        "policy",
        "producer",
        "product_version",
        "runtime",
        "schema",
        "streams",
        "trusted_computing_base",
    ];
    assert_eq!(object.len(), required.len());
    for field in required {
        assert!(object.contains_key(field), "missing required field {field}");
    }
}
