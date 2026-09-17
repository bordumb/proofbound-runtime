"""Independent semantic checks for the proposed service-session observation."""

from __future__ import annotations

import ipaddress
import hashlib
import re

from tools.ci.encode_plan_v2 import encode


class ContractError(ValueError):
    """The proposed observation is incomplete or internally inconsistent."""


PHASES = [
    ("created", "begin-resolution", "resolving"),
    ("resolving", "resolution-complete", "connecting"),
    ("connecting", "endpoint-connected", "authenticating"),
    ("authenticating", "tls-authenticated", "ready"),
    ("ready", "child-released", "active"),
    ("active", "begin-close", "closing"),
    ("closing", "close-complete", "closed"),
]
CREDENTIAL_SOURCE_ID = re.compile(r"(?:[a-z]|[a-z][a-z0-9.-]{0,126}[a-z0-9])\Z")


def exact_keys(value: object, keys: set[str], context: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError(f"{context} does not have the exact closed fields")
    return value


def bounded_integer(value: object, minimum: int, maximum: int, context: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{context} is outside its closed integer bound")
    return value


def fixed_bytes(value: object, length: int, context: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ContractError(f"{context} is not the required byte identity")
    return value


def dns_name(value: object, context: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("ascii", errors="ignore")) <= 253:
        raise ContractError(f"{context} is not a bounded ASCII DNS name")
    if value != value.lower() or value.endswith(".") or any(not label or len(label) > 63 for label in value.split(".")):
        raise ContractError(f"{context} is not canonical")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
    for label in value.split("."):
        if label[0] == "-" or label[-1] == "-" or any(character not in allowed for character in label):
            raise ContractError(f"{context} has an invalid label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ContractError(f"{context} is an IP literal")
    return value


def endpoint(value: object, context: str) -> tuple[int, bytes, int]:
    item = exact_keys(value, {"family", "address", "port"}, context)
    family = item["family"]
    if family not in {"ipv4", "ipv6"}:
        raise ContractError(f"{context} has an unknown address family")
    address = fixed_bytes(item["address"], 4 if family == "ipv4" else 16, f"{context}.address")
    port = bounded_integer(item["port"], 1, 65_535, f"{context}.port")
    return (0 if family == "ipv4" else 1, address, port)


def artifact(value: object, role: str, context: str) -> None:
    item = exact_keys(value, {"role", "size", "mode", "sha256"}, context)
    if item["role"] != role:
        raise ContractError(f"{context} has the wrong artifact role")
    bounded_integer(item["size"], 0, 2**64 - 1, f"{context}.size")
    bounded_integer(item["mode"], 0, 0o7777, f"{context}.mode")
    fixed_bytes(item["sha256"], 32, f"{context}.sha256")


def validate_observation(value: object) -> None:
    root = exact_keys(
        value,
        {
            "schema", "service", "limits", "dns", "tls", "channel", "traffic",
            "cleanup", "lifecycle", "execution_id", "policy_sha256", "connector",
            "credential_source",
        },
        "observation",
    )
    if root["schema"] != "proofbound-runtime-service-session-observation/1":
        raise ContractError("observation has an unknown schema")
    fixed_bytes(root["execution_id"], 16, "execution_id")
    fixed_bytes(root["policy_sha256"], 32, "policy_sha256")

    service = exact_keys(root["service"], {"name", "port"}, "service")
    service_name = dns_name(service["name"], "service.name")
    service_port = bounded_integer(service["port"], 1, 65_535, "service.port")

    limits = exact_keys(
        root["limits"],
        {
            "setup_time_ms", "session_time_ms", "child_to_service_bytes",
            "service_to_child_bytes", "dns_messages", "endpoint_attempts",
            "tls_handshake_bytes",
        },
        "limits",
    )
    for name in limits:
        maximum = 65_535 if name in {"dns_messages", "endpoint_attempts"} else 2**64 - 1
        bounded_integer(limits[name], 1, maximum, f"limits.{name}")

    lifecycle = root["lifecycle"]
    if not isinstance(lifecycle, list) or len(lifecycle) != len(PHASES):
        raise ContractError("lifecycle is not the complete success path")
    lifecycle_times = []
    for index, (transition_value, expected) in enumerate(zip(lifecycle, PHASES, strict=True)):
        transition = exact_keys(transition_value, {"from", "event", "to", "observed_ns"}, f"lifecycle[{index}]")
        if (transition["from"], transition["event"], transition["to"]) != expected:
            raise ContractError("lifecycle contains a skipped or substituted transition")
        lifecycle_times.append(bounded_integer(transition["observed_ns"], 0, 2**64 - 1, f"lifecycle[{index}].observed_ns"))
    if lifecycle_times != sorted(lifecycle_times):
        raise ContractError("lifecycle times are not monotonic")

    connector = exact_keys(
        root["connector"],
        {"executable", "runtime_closure", "runtime_closure_sha256", "process_generation"},
        "connector",
    )
    artifact(connector["executable"], "connector-executable", "connector.executable")
    if not isinstance(connector["runtime_closure"], list):
        raise ContractError("connector.runtime_closure is not an array")
    closure_ids = []
    for index, item in enumerate(connector["runtime_closure"]):
        artifact(item, "connector-runtime-library", f"connector.runtime_closure[{index}]")
        closure_ids.append((item["sha256"], item["size"], item["mode"]))
    if closure_ids != sorted(set(closure_ids)):
        raise ContractError("connector runtime closure is not sorted and unique")
    if fixed_bytes(connector["runtime_closure_sha256"], 32, "connector.runtime_closure_sha256") != hashlib.sha256(
        encode(connector["runtime_closure"])
    ).digest():
        raise ContractError("connector runtime closure identity does not bind its exact bytes")
    bounded_integer(connector["process_generation"], 1, 2**64 - 1, "connector.process_generation")

    dns = exact_keys(
        root["dns"],
        {
            "resolver", "configuration", "maximum_cname_depth",
            "maximum_answer_count", "maximum_response_bytes",
            "resolution_deadline_ms", "attempt_deadline_ms", "address_order",
            "messages", "cname_chain", "answers", "attempts", "selected_endpoint",
        },
        "dns",
    )
    endpoint(dns["resolver"], "dns.resolver")
    artifact(dns["configuration"], "resolver-configuration", "dns.configuration")
    maximum_cname_depth = bounded_integer(dns["maximum_cname_depth"], 1, 65_535, "dns.maximum_cname_depth")
    maximum_answer_count = bounded_integer(dns["maximum_answer_count"], 1, 65_535, "dns.maximum_answer_count")
    maximum_response_bytes = bounded_integer(dns["maximum_response_bytes"], 1, 2**64 - 1, "dns.maximum_response_bytes")
    resolution_deadline_ms = bounded_integer(dns["resolution_deadline_ms"], 1, 2**64 - 1, "dns.resolution_deadline_ms")
    attempt_deadline_ms = bounded_integer(dns["attempt_deadline_ms"], 1, 2**64 - 1, "dns.attempt_deadline_ms")
    if attempt_deadline_ms > resolution_deadline_ms or dns["address_order"] != "ipv4-then-ipv6-lexicographic":
        raise ContractError("DNS timing or address-order policy is not admitted")
    if limits["endpoint_attempts"] > maximum_answer_count:
        raise ContractError("endpoint-attempt bound exceeds the answer-count bound")
    if resolution_deadline_ms > limits["setup_time_ms"]:
        raise ContractError("resolution deadline exceeds the setup deadline")
    if not isinstance(dns["messages"], list) or not 1 <= len(dns["messages"]) <= limits["dns_messages"]:
        raise ContractError("dns message inventory is empty or exceeds its bound")
    message_times = []
    message_observed_ns = {}
    for index, message_value in enumerate(dns["messages"]):
        message = exact_keys(message_value, {"sha256", "size", "observed_ns"}, f"dns.messages[{index}]")
        fixed_bytes(message["sha256"], 32, f"dns.messages[{index}].sha256")
        message_size = bounded_integer(message["size"], 1, 2**64 - 1, f"dns.messages[{index}].size")
        if message_size > maximum_response_bytes:
            raise ContractError("DNS response exceeds its byte bound")
        observed_ns = bounded_integer(message["observed_ns"], 0, 2**64 - 1, f"dns.messages[{index}].observed_ns")
        if message["sha256"] in message_observed_ns:
            raise ContractError("DNS message identities are not unique")
        message_observed_ns[message["sha256"]] = observed_ns
        message_times.append(observed_ns)
    if message_times != sorted(message_times):
        raise ContractError("dns message times are not monotonic")
    if any(time < lifecycle_times[0] or time > lifecycle_times[1] for time in message_times):
        raise ContractError("DNS message is outside the resolution interval")
    if not isinstance(dns["cname_chain"], list) or not dns["cname_chain"]:
        raise ContractError("dns CNAME chain is empty")
    chain = [dns_name(name, "dns.cname_chain") for name in dns["cname_chain"]]
    if chain[0] != service_name or len(chain) != len(set(chain)) or len(chain) - 1 > maximum_cname_depth:
        raise ContractError("dns CNAME chain does not start at the service or contains a loop")
    if not isinstance(dns["answers"], list) or not 1 <= len(dns["answers"]) <= maximum_answer_count:
        raise ContractError("dns answer inventory is empty")
    answers = []
    answer_expirations = []
    for index, answer_value in enumerate(dns["answers"]):
        answer = exact_keys(answer_value, {"name", "endpoint", "message_sha256", "ttl_seconds", "expires_ns"}, f"dns.answers[{index}]")
        if dns_name(answer["name"], f"dns.answers[{index}].name") != chain[-1]:
            raise ContractError("dns answer is not bound to the terminal name")
        answer_endpoint = endpoint(answer["endpoint"], f"dns.answers[{index}].endpoint")
        if answer_endpoint[2] != service_port:
            raise ContractError("dns answer uses an undeclared service port")
        message_identity = fixed_bytes(answer["message_sha256"], 32, f"dns.answers[{index}].message_sha256")
        if message_identity not in message_observed_ns:
            raise ContractError("DNS answer is not bound to a recorded message")
        ttl_seconds = bounded_integer(answer["ttl_seconds"], 1, 2**32 - 1, f"dns.answers[{index}].ttl_seconds")
        expires_ns = bounded_integer(answer["expires_ns"], 1, 2**64 - 1, f"dns.answers[{index}].expires_ns")
        expected_expiry = message_observed_ns[message_identity] + ttl_seconds * 1_000_000_000
        if expected_expiry > 2**64 - 1 or expires_ns != expected_expiry:
            raise ContractError("DNS answer expiry is not derived from its message and TTL")
        answer_expirations.append(expires_ns)
        answers.append(answer_endpoint)
    if answers != sorted(set(answers)):
        raise ContractError("dns answers are not canonical and unique")
    selected = endpoint(dns["selected_endpoint"], "dns.selected_endpoint")
    if selected not in answers:
        raise ContractError("selected endpoint is outside the recorded answer set")
    attempts = dns["attempts"]
    if not isinstance(attempts, list) or not 1 <= len(attempts) <= limits["endpoint_attempts"]:
        raise ContractError("endpoint attempt inventory is empty or exceeds its bound")
    attempted = []
    attempt_times = []
    previous_finish = lifecycle_times[1]
    for index, attempt_value in enumerate(attempts):
        attempt = exact_keys(attempt_value, {"ordinal", "endpoint", "result", "started_ns", "finished_ns"}, f"dns.attempts[{index}]")
        if attempt["ordinal"] != index + 1:
            raise ContractError("endpoint attempt ordinals are not contiguous")
        attempted.append(endpoint(attempt["endpoint"], f"dns.attempts[{index}].endpoint"))
        if attempt["result"] not in {"refused", "timed-out", "failed", "connected"}:
            raise ContractError("endpoint attempt has an unknown result")
        if (attempt["result"] == "connected") != (index == len(attempts) - 1):
            raise ContractError("only the terminal endpoint attempt can connect")
        started_ns = bounded_integer(attempt["started_ns"], 0, 2**64 - 1, f"dns.attempts[{index}].started_ns")
        finished_ns = bounded_integer(attempt["finished_ns"], 0, 2**64 - 1, f"dns.attempts[{index}].finished_ns")
        if started_ns < previous_finish or finished_ns < started_ns or finished_ns - started_ns > attempt_deadline_ms * 1_000_000:
            raise ContractError("endpoint attempt exceeds its deadline")
        attempted_answer = answers.index(attempted[-1])
        if finished_ns >= answer_expirations[attempted_answer]:
            raise ContractError("endpoint attempt used an expired DNS answer")
        previous_finish = finished_ns
        attempt_times.append(finished_ns)
    if attempted != answers[: len(attempted)] or attempted[-1] != selected:
        raise ContractError("endpoint attempts do not follow the canonical answer prefix")
    if attempt_times != sorted(attempt_times):
        raise ContractError("endpoint attempt times are not monotonic")
    if attempt_times[-1] != lifecycle_times[2]:
        raise ContractError("endpoint-connected is not bound to the selected attempt")

    tls = exact_keys(
        root["tls"],
        {
            "implementation_sha256", "version", "service_name_verification", "certificate_chain_sha256",
            "trust_root_set", "revocation", "session_resumption", "early_data",
            "handshake_bytes", "authenticated_ns",
        },
        "tls",
    )
    fixed_bytes(tls["implementation_sha256"], 32, "tls.implementation_sha256")
    if tls["version"] not in {"tls-1.2", "tls-1.3"} or tls["service_name_verification"] != "dns-san-exact-match":
        raise ContractError("TLS identity observation is not admitted")
    fixed_bytes(tls["certificate_chain_sha256"], 32, "tls.certificate_chain_sha256")
    artifact(tls["trust_root_set"], "trust-root-set", "tls.trust_root_set")
    if tls["revocation"] != "not-checked-recorded-assumption" or tls["session_resumption"] != "not-used" or tls["early_data"] != "not-used":
        raise ContractError("TLS policy observation is incomplete")
    handshake_bytes = bounded_integer(tls["handshake_bytes"], 1, 2**64 - 1, "tls.handshake_bytes")
    if handshake_bytes > limits["tls_handshake_bytes"]:
        raise ContractError("TLS handshake exceeds its bound")
    authenticated_ns = bounded_integer(tls["authenticated_ns"], 0, 2**64 - 1, "tls.authenticated_ns")
    if authenticated_ns < attempt_times[-1]:
        raise ContractError("TLS authentication precedes the selected connection")
    if authenticated_ns >= answer_expirations[answers.index(selected)]:
        raise ContractError("TLS completed after the selected DNS answer expired")

    channel = exact_keys(root["channel"], {"protocol", "child_descriptor", "channel_id", "descriptor_state"}, "channel")
    if channel["protocol"] != "unix-stream-v1" or channel["descriptor_state"] != "registered-only":
        raise ContractError("local channel observation is not admitted")
    bounded_integer(channel["child_descriptor"], 3, 65_535, "channel.child_descriptor")
    fixed_bytes(channel["channel_id"], 16, "channel.channel_id")

    traffic = exact_keys(root["traffic"], {"child_to_service_bytes", "service_to_child_bytes", "active_ns", "closed_ns"}, "traffic")
    for direction in ("child_to_service_bytes", "service_to_child_bytes"):
        count = bounded_integer(traffic[direction], 0, 2**64 - 1, f"traffic.{direction}")
        if count > limits[direction]:
            raise ContractError(f"traffic.{direction} exceeds its bound")
    active_ns = bounded_integer(traffic["active_ns"], 0, 2**64 - 1, "traffic.active_ns")
    closed_ns = bounded_integer(traffic["closed_ns"], 0, 2**64 - 1, "traffic.closed_ns")
    if closed_ns < active_ns:
        raise ContractError("traffic closes before it becomes active")

    if lifecycle_times != sorted(lifecycle_times) or lifecycle_times[3] != authenticated_ns or lifecycle_times[4] != active_ns or lifecycle_times[-1] != closed_ns:
        raise ContractError("lifecycle times are inconsistent with TLS or traffic observations")
    if lifecycle_times[1] - lifecycle_times[0] > resolution_deadline_ms * 1_000_000:
        raise ContractError("resolution exceeds its deadline")
    if lifecycle_times[3] - lifecycle_times[0] > limits["setup_time_ms"] * 1_000_000:
        raise ContractError("service setup exceeds its deadline")
    if lifecycle_times[-1] - lifecycle_times[4] > limits["session_time_ms"] * 1_000_000:
        raise ContractError("service session exceeds its deadline")

    cleanup = exact_keys(root["cleanup"], {"connector", "channel", "child", "cgroup", "namespace"}, "cleanup")
    if cleanup != {"connector": "reaped", "channel": "closed", "child": "reaped", "cgroup": "empty-removed", "namespace": "destroyed"}:
        raise ContractError("cleanup is not complete")

    credential = root["credential_source"]
    if credential is not None:
        credential = exact_keys(credential, {"id", "service", "environment"}, "credential_source")
        credential_id = credential["id"]
        if (
            not isinstance(credential_id, str)
            or not 1 <= len(credential_id.encode("utf-8")) <= 128
            or CREDENTIAL_SOURCE_ID.fullmatch(credential_id) is None
        ):
            raise ContractError("credential source id is invalid")
        if dns_name(credential["service"], "credential_source.service") != service_name:
            raise ContractError("credential source is bound to another service")
        environment = credential["environment"]
        if (
            not isinstance(environment, str)
            or not 1 <= len(environment) <= 255
            or not (
                environment[0].isascii()
                and (environment[0].isalpha() or environment[0] == "_")
            )
            or any(not (character.isascii() and (character.isalnum() or character == "_")) for character in environment)
        ):
            raise ContractError("credential environment name is invalid")

    forbidden = {"credential_value", "secret", "request_bytes", "response_bytes", "application_bytes"}
    stack = [root]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if forbidden.intersection(current):
                raise ContractError("observation contains retained secret or application content")
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
