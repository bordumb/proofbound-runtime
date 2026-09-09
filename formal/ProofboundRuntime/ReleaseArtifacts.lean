import Proofbound.Artifact
import Proofbound.Attribute

namespace ProofboundRuntime.ReleaseArtifacts

/-!
The byte constants name the two exact native `pbr` executables abstractly. The
closed digest-set theorems and contextual artifact checker connect those names
to release bytes. `toolchainWitness` is deliberately the sole project axiom:
it records the compiler, linker, and build-preservation boundary rather than
disguising a build or empirical execution as proof.
-/

opaque aarch64PbrBytes : ByteArray := ByteArray.empty
opaque x86_64PbrBytes : ByteArray := ByteArray.empty

opaque artifactCarries (bytes : ByteArray) (claimId : String) : Prop := False

structure ToolchainWitness : Prop where
  aarch64Digest :
    "sha256:" ++ Proofbound.sha256Hex aarch64PbrBytes =
      "sha256:cb0c7d719aa4ab1cf07f189f4a8d770872b469dd7b97a51f7d9a4d35bfd9f1f9"
  x86_64Digest :
    "sha256:" ++ Proofbound.sha256Hex x86_64PbrBytes =
      "sha256:9b69640708ddad502ee55d35be62cc4080ba4b5b31d8ecc92fc1cb7c73d80e2a"
  authorityAarch64 : artifactCarries aarch64PbrBytes "PBR-AUTH-001"
  authorityX86_64 : artifactCarries x86_64PbrBytes "PBR-AUTH-001"
  policyAarch64 : artifactCarries aarch64PbrBytes "PBR-POLICY-002"
  policyX86_64 : artifactCarries x86_64PbrBytes "PBR-POLICY-002"
  receiptEligibilityAarch64 : artifactCarries aarch64PbrBytes "PBR-RECEIPT-004"
  receiptEligibilityX86_64 : artifactCarries x86_64PbrBytes "PBR-RECEIPT-004"
  receiptBindingAarch64 : artifactCarries aarch64PbrBytes "PBR-BINDING-005"
  receiptBindingX86_64 : artifactCarries x86_64PbrBytes "PBR-BINDING-005"

@[proofbound_exempt "Explicit PBR-TOOLCHAIN-AX-003 witness for exact native pbr bytes."]
axiom toolchainWitness : ToolchainWitness

end ProofboundRuntime.ReleaseArtifacts
