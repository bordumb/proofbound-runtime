#![forbid(unsafe_code)]
#![no_std]

//! Defines the pure receipt field-binding construction and projection boundary.

extern crate alloc;

use alloc::vec::Vec;

/// Contains the canonical bytes of every supported top-level receipt field.
///
/// A field is represented by its version-specific canonical value bytes,
/// excluding the top-level field name. Version 1 uses canonical JSON and omits
/// `resources`; version 2 uses deterministic CBOR and requires it. Using a
/// closed structure makes omission, duplication, reordering, and unknown
/// top-level fields unrepresentable at the production construction boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBindingParts {
    pub assumptions: Vec<u8>,
    pub boundary: Vec<u8>,
    pub command: Vec<u8>,
    pub eligibility: Vec<u8>,
    pub environment: Vec<u8>,
    pub execution_id: Vec<u8>,
    pub inputs: Vec<u8>,
    pub observations: Vec<u8>,
    pub outcome: Vec<u8>,
    pub output_root: Vec<u8>,
    pub outputs: Vec<u8>,
    pub plan: Vec<u8>,
    pub platform: Vec<u8>,
    pub policy: Vec<u8>,
    pub producer: Vec<u8>,
    pub product_version: Vec<u8>,
    pub resources: Option<Vec<u8>>,
    pub runtime: Vec<u8>,
    pub schema: Vec<u8>,
    pub streams: Vec<u8>,
    pub trusted_computing_base: Vec<u8>,
}

/// Contains one constructed closed receipt binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBinding {
    parts: ReceiptBindingParts,
}

/// Constructs a receipt binding without changing any canonical field value.
#[must_use]
pub fn construct_receipt_binding(parts: ReceiptBindingParts) -> ReceiptBinding {
    ReceiptBinding { parts }
}

/// Projects a constructed receipt binding back to its canonical wire fields.
#[must_use]
pub fn project_receipt_binding(binding: ReceiptBinding) -> ReceiptBindingParts {
    binding.parts
}

/// Runs the exact construction and projection path used by the wire encoder.
#[must_use]
pub fn construct_and_project_receipt_binding(parts: ReceiptBindingParts) -> ReceiptBindingParts {
    project_receipt_binding(construct_receipt_binding(parts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn parts() -> ReceiptBindingParts {
        ReceiptBindingParts {
            assumptions: vec![0],
            boundary: vec![1],
            command: vec![2],
            eligibility: vec![3],
            environment: vec![4],
            execution_id: vec![5],
            inputs: vec![6],
            observations: vec![7],
            outcome: vec![8],
            output_root: vec![9],
            outputs: vec![10],
            plan: vec![11],
            platform: vec![12],
            policy: vec![13],
            producer: vec![14],
            product_version: vec![15],
            resources: None,
            runtime: vec![16],
            schema: vec![17],
            streams: vec![18],
            trusted_computing_base: vec![19],
        }
    }

    #[test]
    fn construction_and_projection_retain_all_v1_fields_exactly() {
        let input = parts();
        let output = construct_and_project_receipt_binding(input.clone());
        assert_eq!(output, input);
    }

    #[test]
    fn construction_and_projection_retain_all_v2_fields_exactly() {
        let mut input = parts();
        input.resources = Some(vec![20]);
        let output = construct_and_project_receipt_binding(input.clone());
        assert_eq!(output, input);
    }
}
