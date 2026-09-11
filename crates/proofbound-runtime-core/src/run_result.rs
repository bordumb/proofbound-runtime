#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::{ExecutionId, ExecutionOutcome, Sha256Digest};

    #[test]
    fn version_two_run_result_matches_the_frozen_cbor_golden() {
        let execution_id = ExecutionId::from_bytes([
            0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
        ])
        .expect("golden execution ID is version 4");
        let result = super::RunResultV2::new(
            Path::new("receipt.cbor"),
            execution_id,
            Sha256Digest::from_bytes([9; 32]),
            ExecutionOutcome::Exited { code: 0 },
        )
        .expect("golden run result is valid");
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v2/run-result.cbor.hex"
        ))
        .split_whitespace()
        .collect::<String>();
        assert_eq!(encode_hex(&result.canonical_bytes()), expected);
        assert_eq!(
            result.json_projection()["schema"],
            "proofbound-runtime-run-result/2"
        );
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
