"""Independent checks for the proposed service-session receipt fragment."""

from __future__ import annotations

import hashlib

from tools.ci.deterministic_cbor import CborError, decode_strict
from tools.ci.encode_plan_v2 import encode
from tools.ci.service_launcher_contract import (
    ContractError as LauncherError,
    validate_retained_transcript,
)
from tools.ci.service_observation_contract import (
    ContractError as ObservationError,
    bounded_integer,
    dns_name,
    exact_keys,
    fixed_bytes,
    validate_observation,
)


class ContractError(ValueError):
    """The receipt fragment is malformed or semantically inconsistent."""


REQUIRED_ASSUMPTIONS = [
    "PBR-DNS-AX-004",
    "PBR-TLS-AX-005",
]
REQUIRED_TCB_ROLES = [
    "connector-executable",
    "connector-runtime-closure",
    "tls-implementation",
    "tls-trust-roots",
]
FAILURE_PHASES = {
    "connector-start-failed": {"created"},
    "resolver-failed": {"resolving"},
    "endpoints-exhausted": {"connecting"},
    "tls-authentication-failed": {"authenticating"},
    "launcher-install-failed": {"ready"},
    "launcher-release-failed": {"ready"},
    "service-limit-exceeded": {"active"},
    "channel-lost": {"active", "closing"},
    "child-failed": {"active", "closing"},
    "cleanup-failed": {"created", "resolving", "connecting", "authenticating", "ready", "active", "closing"},
    "evidence-incomplete": {"created", "resolving", "connecting", "authenticating", "ready", "active", "closing"},
}


def strict_strings(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ContractError(f"{context} is not a nonempty text set")
    if any(left.encode() >= right.encode() for left, right in zip(value, value[1:])):
        raise ContractError(f"{context} is not strictly ordered")
    return value


def validate_tcb(value: object, expected_identities: dict[str, bytes]) -> dict[str, bytes]:
    if not isinstance(value, list) or not value:
        raise ContractError("trusted computing base is empty")
    if not isinstance(expected_identities, dict):
        raise ContractError("expected trusted computing base is not a role map")
    roles = []
    identities = {}
    for index, raw in enumerate(value):
        entry = exact_keys(raw, {"role", "identity_sha256"}, f"trusted_computing_base[{index}]")
        if not isinstance(entry["role"], str) or not entry["role"] or len(entry["role"].encode()) > 128:
            raise ContractError("trusted computing base role is outside its bound")
        identity = fixed_bytes(
            entry["identity_sha256"],
            32,
            f"trusted_computing_base[{index}].identity_sha256",
        )
        roles.append(entry["role"])
        identities[entry["role"]] = identity
    if roles != REQUIRED_TCB_ROLES:
        raise ContractError("trusted computing base roles are incomplete or unordered")
    if set(expected_identities) != set(REQUIRED_TCB_ROLES):
        raise ContractError("expected trusted computing base roles are incomplete")
    for role in REQUIRED_TCB_ROLES:
        if identities[role] != fixed_bytes(
            expected_identities[role], 32, f"expected_tcb_identities[{role}]"
        ):
            raise ContractError("trusted computing base identity is substituted")
    return identities


def validate_receipt(
    value: object,
    *,
    expected_execution_id: bytes,
    expected_plan_sha256: bytes,
    expected_policy_sha256: bytes,
    expected_service_name: str,
    expected_service_port: int,
    expected_tcb_identities: dict[str, bytes],
    install_request_cbor: bytes | None,
    installed_cbor: bytes | None,
    release_cbor: bytes | None,
) -> None:
    try:
        root = exact_keys(
            value,
            {
                "schema", "service", "result", "eligibility", "execution_id",
                "plan_sha256", "policy_sha256", "install_request_sha256",
                "assumptions", "trusted_computing_base",
            },
            "receipt",
        )
        if root["schema"] != "proofbound-runtime-service-session-receipt/1":
            raise ContractError("receipt schema is unknown")
        execution_id = fixed_bytes(root["execution_id"], 16, "execution_id")
        if execution_id != fixed_bytes(expected_execution_id, 16, "expected_execution_id"):
            raise ContractError("receipt does not bind the expected execution")
        if fixed_bytes(root["plan_sha256"], 32, "plan_sha256") != fixed_bytes(
            expected_plan_sha256, 32, "expected_plan_sha256"
        ):
            raise ContractError("receipt does not bind the exact execution plan")
        policy_sha256 = fixed_bytes(root["policy_sha256"], 32, "policy_sha256")
        if policy_sha256 != fixed_bytes(expected_policy_sha256, 32, "expected_policy_sha256"):
            raise ContractError("receipt does not bind the expected compiled policy")

        service = exact_keys(root["service"], {"name", "port"}, "service")
        service_name = dns_name(service["name"], "service.name")
        service_port = bounded_integer(service["port"], 1, 65_535, "service.port")
        if service_name != dns_name(expected_service_name, "expected_service_name") or service_port != bounded_integer(
            expected_service_port, 1, 65_535, "expected_service_port"
        ):
            raise ContractError("receipt does not bind the expected service")
        if strict_strings(root["assumptions"], "assumptions") != REQUIRED_ASSUMPTIONS:
            raise ContractError("required assumptions are incomplete")
        tcb_identities = validate_tcb(
            root["trusted_computing_base"], expected_tcb_identities
        )

        eligibility = exact_keys(root["eligibility"], {"status", "reasons"}, "eligibility")
        result = root["result"]
        if not isinstance(result, dict):
            raise ContractError("result is not a map")

        launcher_messages = []
        if install_request_cbor is None:
            if installed_cbor is not None or release_cbor is not None:
                raise ContractError("launcher suffix exists without an install request")
            install_request = None
            install_request_sha256 = None
            installed_sha256 = None
            release_sha256 = None
        else:
            launcher_payloads = [("install request", install_request_cbor)]
            if installed_cbor is not None:
                launcher_payloads.append(("installed acknowledgement", installed_cbor))
            if release_cbor is not None:
                launcher_payloads.append(("release", release_cbor))
            for context, payload in launcher_payloads:
                if not isinstance(payload, bytes) or not 1 <= len(payload) <= 1_048_576:
                    raise ContractError(f"{context} bytes are outside the frame bound")
                message = decode_strict(payload)
                if encode(message) != payload:
                    raise ContractError(f"{context} bytes do not round trip canonically")
                launcher_messages.append(message)
            validate_retained_transcript(launcher_messages)
            install_request = launcher_messages[0]
            install_request_sha256 = hashlib.sha256(install_request_cbor).digest()
            installed_sha256 = hashlib.sha256(installed_cbor).digest() if installed_cbor is not None else None
            release_sha256 = hashlib.sha256(release_cbor).digest() if release_cbor is not None else None

        recorded_install = root["install_request_sha256"]
        if install_request_sha256 is None:
            if recorded_install is not None:
                raise ContractError("receipt claims an absent launcher install request")
        elif fixed_bytes(recorded_install, 32, "install_request_sha256") != install_request_sha256:
            raise ContractError("receipt does not bind the exact launcher install request")
        if install_request is not None:
            launcher_service = install_request["service"]["service"]
            if (
                install_request["execution_id"] != execution_id
                or install_request["policy_sha256"] != policy_sha256
                or launcher_service != {"name": service_name, "port": service_port}
            ):
                raise ContractError("receipt context is inconsistent with the launcher request")

        if result.get("kind") == "success":
            if install_request is None:
                raise ContractError("success omits the retained launcher install request")
            validate_success(
                result,
                eligibility,
                execution_id,
                policy_sha256,
                service_name,
                service_port,
                tcb_identities,
                install_request,
                installed_sha256,
                release_sha256,
            )
        elif result.get("kind") == "failed":
            validate_failure(
                result,
                eligibility,
                install_request_sha256,
                installed_sha256,
                release_sha256,
            )
        else:
            raise ContractError("result kind is unknown")
    except (CborError, LauncherError, ObservationError) as error:
        raise ContractError(str(error)) from error


def validate_success(
    result: dict,
    eligibility: dict,
    execution_id: bytes,
    policy_sha256: bytes,
    service_name: str,
    service_port: int,
    tcb_identities: dict[str, bytes],
    install_request: dict,
    expected_installed_sha256: bytes | None,
    expected_release_sha256: bytes | None,
) -> None:
    result = exact_keys(
        result,
        {
            "kind", "release_sha256", "installed_sha256", "observation_cbor",
            "observation_sha256", "child_outcome",
        },
        "result",
    )
    if eligibility != {"status": "reusable", "reasons": []}:
        raise ContractError("successful receipt is not exactly reusable")
    if expected_release_sha256 is None:
        raise ContractError("success omits the retained launcher release")
    if fixed_bytes(result["release_sha256"], 32, "release_sha256") != fixed_bytes(
        expected_release_sha256, 32, "expected_release_sha256"
    ):
        raise ContractError("success does not bind the exact launcher release")
    if expected_installed_sha256 is None:
        raise ContractError("success omits the retained installed acknowledgement")
    if fixed_bytes(result["installed_sha256"], 32, "installed_sha256") != fixed_bytes(
        expected_installed_sha256, 32, "expected_installed_sha256"
    ):
        raise ContractError("success does not bind the exact installed acknowledgement")
    observation_bytes = result["observation_cbor"]
    if not isinstance(observation_bytes, bytes) or not 1 <= len(observation_bytes) <= 1_048_576:
        raise ContractError("observation bytes are outside the frame bound")
    expected = hashlib.sha256(observation_bytes).digest()
    if fixed_bytes(result["observation_sha256"], 32, "observation_sha256") != expected:
        raise ContractError("observation identity does not bind its exact bytes")
    try:
        observation = decode_strict(observation_bytes)
    except CborError as error:
        raise ContractError("observation bytes are not strict deterministic CBOR") from error
    if encode(observation) != observation_bytes:
        raise ContractError("observation bytes do not round trip canonically")
    validate_observation(observation)
    if observation["execution_id"] != execution_id or observation["policy_sha256"] != policy_sha256:
        raise ContractError("observation execution or policy identity is substituted")
    if observation["service"] != {"name": service_name, "port": service_port}:
        raise ContractError("observation service is substituted")
    service_binding = install_request["service"]
    if observation["connector"]["executable"] != service_binding["connector"]["executable"]:
        raise ContractError("observation connector executable is inconsistent with the launcher")
    if observation["connector"]["runtime_closure_sha256"] != service_binding["connector"]["runtime_closure_sha256"]:
        raise ContractError("observation connector closure is inconsistent with the launcher")
    if observation["connector"]["process_generation"] != service_binding["connector"]["process_generation"]:
        raise ContractError("observation connector generation is inconsistent with the launcher")
    if observation["dns"]["selected_endpoint"] != service_binding["selected_endpoint"]:
        raise ContractError("observation endpoint is inconsistent with the launcher")
    if hashlib.sha256(encode(observation["dns"])).digest() != service_binding["dns_observation_sha256"]:
        raise ContractError("DNS observation identity is inconsistent with the launcher")
    if hashlib.sha256(encode(observation["tls"])).digest() != service_binding["tls_observation_sha256"]:
        raise ContractError("TLS observation identity is inconsistent with the launcher")
    if observation["limits"] != service_binding["limits"]:
        raise ContractError("observation limits are inconsistent with the launcher")
    if (
        observation["channel"]["child_descriptor"] != service_binding["channel"]["child_descriptor"]
        or observation["channel"]["channel_id"] != service_binding["channel"]["child_endpoint_id"]
    ):
        raise ContractError("observation channel is inconsistent with the launcher")
    if observation["credential_source"] != service_binding["credential_source"]:
        raise ContractError("observation credential source is inconsistent with the launcher")
    if observation["connector"]["executable"]["sha256"] != tcb_identities["connector-executable"]:
        raise ContractError("connector trusted computing base identity is inconsistent")
    if observation["connector"]["runtime_closure_sha256"] != tcb_identities["connector-runtime-closure"]:
        raise ContractError("connector closure trusted computing base identity is inconsistent")
    if observation["tls"]["implementation_sha256"] != tcb_identities["tls-implementation"]:
        raise ContractError("TLS implementation trusted computing base identity is inconsistent")
    if observation["tls"]["trust_root_set"]["sha256"] != tcb_identities["tls-trust-roots"]:
        raise ContractError("trust-root trusted computing base identity is inconsistent")
    if result["child_outcome"] != {"kind": "exited", "code": 0}:
        raise ContractError("reusable success requires child exit zero")


def validate_failure(
    result: dict,
    eligibility: dict,
    expected_install_request_sha256: bytes | None,
    expected_installed_sha256: bytes | None,
    expected_release_sha256: bytes | None,
) -> None:
    result = exact_keys(
        result,
        {
            "kind", "phase", "reason", "observed_ns", "boundary_state",
            "clock", "installed_sha256", "release_sha256", "observation_sha256", "cleanup",
        },
        "result",
    )
    reason = result["reason"]
    phase = result["phase"]
    if reason not in FAILURE_PHASES or phase not in FAILURE_PHASES[reason]:
        raise ContractError("failure reason is inconsistent with its phase")
    if result["clock"] != "linux-monotonic":
        raise ContractError("failure clock is unknown")
    bounded_integer(result["observed_ns"], 0, 2**64 - 1, "observed_ns")
    if result["observation_sha256"] is not None:
        raise ContractError("failed receipt cannot retain a success observation identity")
    boundary_state = result["boundary_state"]
    before_launcher = phase in {"created", "resolving", "connecting", "authenticating"}
    if before_launcher and expected_install_request_sha256 is not None:
        raise ContractError("pre-launch failure retains a premature install request")
    if reason == "launcher-install-failed" and expected_install_request_sha256 is None:
        raise ContractError("launcher installation failure omits its install request")
    if (boundary_state == "installed" or phase in {"active", "closing"}) and expected_install_request_sha256 is None:
        raise ContractError("launcher-progress failure omits its install request")
    if boundary_state == "installed":
        if expected_installed_sha256 is None:
            raise ContractError("installed failure omits the retained acknowledgement")
        if fixed_bytes(result["installed_sha256"], 32, "installed_sha256") != fixed_bytes(
            expected_installed_sha256, 32, "expected_installed_sha256"
        ):
            raise ContractError("failure does not bind the exact installed acknowledgement")
    elif boundary_state == "not-installed":
        if expected_installed_sha256 is not None:
            raise ContractError("uninstalled failure retains a premature acknowledgement")
        if result["installed_sha256"] is not None:
            raise ContractError("uninstalled boundary has an installed identity")
    else:
        raise ContractError("boundary state is unknown")
    if phase in {"created", "resolving", "connecting", "authenticating"} and boundary_state != "not-installed":
        raise ContractError("early failure claims an installed boundary")
    if reason == "launcher-install-failed" and boundary_state != "not-installed":
        raise ContractError("launcher installation failure claims an installed boundary")
    if reason == "launcher-release-failed" and boundary_state != "installed":
        raise ContractError("launcher release failure omits the installed boundary")
    if phase in {"active", "closing"}:
        if boundary_state != "installed":
            raise ContractError("post-release failure omits the installed boundary")
        if expected_release_sha256 is None:
            raise ContractError("post-release failure omits the retained release")
        if fixed_bytes(result["release_sha256"], 32, "release_sha256") != fixed_bytes(
            expected_release_sha256, 32, "expected_release_sha256"
        ):
            raise ContractError("post-release failure does not bind the exact release")
    else:
        if expected_release_sha256 is not None:
            raise ContractError("pre-release failure retains a premature release")
        if result["release_sha256"] is not None:
            raise ContractError("pre-release failure claims a release identity")

    cleanup = exact_keys(result["cleanup"], {"child", "channel", "cgroup", "connector", "namespace"}, "cleanup")
    allowed = {
        "child": {"not-started", "reaped", "cleanup-failed"},
        "channel": {"closed", "cleanup-failed"},
        "cgroup": {"empty-removed", "cleanup-failed"},
        "connector": {"not-started", "reaped", "cleanup-failed"},
        "namespace": {"destroyed", "cleanup-failed"},
    }
    if any(cleanup[name] not in values for name, values in allowed.items()):
        raise ContractError("cleanup state is unknown")
    failed_cleanup = any(value == "cleanup-failed" for value in cleanup.values())
    if (reason == "cleanup-failed") != failed_cleanup:
        raise ContractError("cleanup failure reason and observations disagree")
    if phase not in {"active", "closing"} and cleanup["child"] != "not-started":
        raise ContractError("pre-release failure claims a reaped child")
    if phase in {"active", "closing"} and cleanup["child"] == "not-started":
        raise ContractError("post-release failure claims that the child did not start")
    if phase != "created" and cleanup["connector"] == "not-started":
        raise ContractError("started connector is recorded as absent")
    if phase == "created" and cleanup["connector"] != "not-started":
        raise ContractError("unstarted connector is recorded as reaped")

    expected_reason = f"network.{reason}"
    if eligibility != {"status": "non-reusable", "reasons": [expected_reason]}:
        raise ContractError("failure eligibility does not retain the exact reason")
