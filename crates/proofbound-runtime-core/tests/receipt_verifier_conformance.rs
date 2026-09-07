use proofbound_runtime_core::{
    Architecture, ArtifactIdentity, ArtifactRole, BoundaryInstallation, BoundaryRecord,
    CgroupIdentity, EnvironmentName, ExecutionId, ExecutionObservations, ExecutionOutcome,
    ExecutionReceipt, ExecutionReceiptParts, FileMode, REQUIRED_RUNTIME_ASSUMPTIONS,
    ReceiptCommand, ReceiptPlan, ReceiptPolicy, ReceiptStreams, RuntimeIdentity, Sha256Digest,
    StreamCapture, TrustedComputingBaseEntry, TrustedComputingBaseRole,
};
use proofbound_runtime_verify::{
    EligibilityDecision, FailureReason, ReceiptCommitment, verify_receipt,
};

fn artifact(role: ArtifactRole, marker: u8) -> ArtifactIdentity {
    ArtifactIdentity::new(
        role,
        Sha256Digest::from_bytes([marker; 32]),
        u64::from(marker),
        FileMode::new(0o640).expect("fixture mode is valid"),
    )
}

fn execution_id() -> ExecutionId {
    ExecutionId::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ])
    .expect("fixture execution ID is version 4")
}

fn tcb() -> Vec<TrustedComputingBaseEntry> {
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

fn parts(outcome: ExecutionOutcome) -> ExecutionReceiptParts {
    let execution_id = execution_id();
    let policy = artifact(ArtifactRole::CompiledPolicy, 3);
    let runtime = artifact(ArtifactRole::RuntimeBinary, 4);
    ExecutionReceiptParts {
        execution_id,
        plan: ReceiptPlan::new(
            proofbound_runtime_core::PlanId::new("conformance.plan")
                .expect("fixture plan ID is valid"),
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
        observations: ExecutionObservations::new(15, 16).expect("fixture observations are ordered"),
        streams: ReceiptStreams::new(
            artifact(ArtifactRole::StandardOutput, 17),
            StreamCapture::Complete,
            artifact(ArtifactRole::StandardError, 18),
            StreamCapture::Complete,
        )
        .expect("fixture stream roles are valid"),
        outcome,
        outputs: vec![artifact(ArtifactRole::OutputArtifact, 19)],
        producer: runtime,
        assumptions: REQUIRED_RUNTIME_ASSUMPTIONS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        trusted_computing_base: tcb(),
    }
}

#[test]
fn producer_bytes_verify_as_reusable() {
    let receipt = ExecutionReceipt::new(parts(ExecutionOutcome::Exited { code: 0 }))
        .expect("producer accepts fixture");
    let bytes = receipt.canonical_bytes().expect("producer encodes fixture");
    let report = verify_receipt(&bytes, ReceiptCommitment::for_bytes(&bytes))
        .expect("independent verifier accepts producer bytes");
    assert_eq!(report.eligibility(), &EligibilityDecision::Reusable);
}

#[test]
fn producer_and_verifier_agree_on_non_reuse() {
    let receipt =
        ExecutionReceipt::new(parts(ExecutionOutcome::Denied)).expect("producer accepts denial");
    let bytes = receipt.canonical_bytes().expect("producer encodes denial");
    let report = verify_receipt(&bytes, ReceiptCommitment::for_bytes(&bytes))
        .expect("independent verifier accepts producer denial");
    let EligibilityDecision::NonReusable(reasons) = report.eligibility() else {
        panic!("denied execution must not be reusable");
    };
    assert_eq!(reasons.as_slice(), &[FailureReason::Denied]);
}
