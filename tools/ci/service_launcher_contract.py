"""Independent checks for the proposed service-session launcher handshake."""

from __future__ import annotations

import hashlib
import re

from tools.ci.encode_plan_v2 import encode
from tools.ci.service_observation_contract import dns_name


class ContractError(ValueError):
    """The launcher handshake is incomplete or internally inconsistent."""


CREDENTIAL_SOURCE_ID = re.compile(r"(?:[a-z]|[a-z][a-z0-9.-]{0,126}[a-z0-9])\Z")
MAX_LAUNCHER_FRAME_BYTES = 1_048_576


def exact_map(value: object, keys: set[str], context: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError(f"{context} does not have the exact closed fields")
    return value


def integer(value: object, minimum: int, maximum: int, context: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{context} is outside its closed integer bound")
    return value


def bytes_exact(value: object, length: int, context: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ContractError(f"{context} is not the required byte identity")
    return value


def environment_name(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value.encode("utf-8")) <= 255
        or "\0" in value
        or "=" in value
    ):
        raise ContractError(f"{context} is not an admitted environment name")
    return value


def artifact(value: object, role: str, context: str) -> None:
    item = exact_map(value, {"role", "sha256", "size", "mode"}, context)
    if item["role"] != role:
        raise ContractError(f"{context} has the wrong role")
    bytes_exact(item["sha256"], 32, f"{context}.sha256")
    integer(item["size"], 0, 2**64 - 1, f"{context}.size")
    integer(item["mode"], 0, 0o7777, f"{context}.mode")


def cgroup(value: object, context: str) -> tuple[int, int]:
    item = exact_map(value, {"mount_id", "inode"}, context)
    return (
        integer(item["mount_id"], 1, 2**64 - 1, f"{context}.mount_id"),
        integer(item["inode"], 1, 2**64 - 1, f"{context}.inode"),
    )


def endpoint(value: object, context: str) -> None:
    item = exact_map(value, {"family", "address", "port"}, context)
    if item["family"] not in {"ipv4", "ipv6"}:
        raise ContractError(f"{context} has an unknown address family")
    bytes_exact(item["address"], 4 if item["family"] == "ipv4" else 16, f"{context}.address")
    integer(item["port"], 1, 65_535, f"{context}.port")


def service_binding(value: object) -> None:
    service = exact_map(
        value,
        {
            "service", "connector", "dns_observation_sha256", "selected_endpoint",
            "tls_observation_sha256", "channel", "limits", "child_filter_sha256",
            "credential_source",
        },
        "service",
    )
    identity = exact_map(service["service"], {"name", "port"}, "service.service")
    declared_name = dns_name(identity["name"], "service.service.name")
    declared_port = integer(identity["port"], 1, 65_535, "service.service.port")
    connector = exact_map(service["connector"], {"executable", "runtime_closure_sha256", "process_generation"}, "service.connector")
    artifact(connector["executable"], "connector-executable", "service.connector.executable")
    bytes_exact(connector["runtime_closure_sha256"], 32, "service.connector.runtime_closure_sha256")
    integer(connector["process_generation"], 1, 2**64 - 1, "service.connector.process_generation")
    bytes_exact(service["dns_observation_sha256"], 32, "service.dns_observation_sha256")
    endpoint(service["selected_endpoint"], "service.selected_endpoint")
    if service["selected_endpoint"]["port"] != declared_port:
        raise ContractError("selected endpoint uses an undeclared service port")
    bytes_exact(service["tls_observation_sha256"], 32, "service.tls_observation_sha256")
    bytes_exact(service["child_filter_sha256"], 32, "service.child_filter_sha256")

    channel = exact_map(
        service["channel"],
        {"protocol", "connector_endpoint_id", "child_endpoint_id", "child_descriptor", "role"},
        "service.channel",
    )
    if channel["protocol"] != "unix-stream-v1" or channel["role"] != "service-session-channel":
        raise ContractError("service channel has an unknown protocol or role")
    connector_endpoint = bytes_exact(channel["connector_endpoint_id"], 16, "service.channel.connector_endpoint_id")
    child_endpoint = bytes_exact(channel["child_endpoint_id"], 16, "service.channel.child_endpoint_id")
    if connector_endpoint == child_endpoint:
        raise ContractError("service channel endpoint identities are equal")
    integer(channel["child_descriptor"], 3, 65_535, "service.channel.child_descriptor")

    limits = exact_map(
        service["limits"],
        {
            "setup_time_ms", "session_time_ms", "child_to_service_bytes",
            "service_to_child_bytes", "dns_messages", "endpoint_attempts",
            "tls_handshake_bytes",
        },
        "service.limits",
    )
    for name, value in limits.items():
        maximum = 65_535 if name in {"dns_messages", "endpoint_attempts"} else 2**64 - 1
        minimum = 2 if name == "dns_messages" else 1
        integer(value, minimum, maximum, f"service.limits.{name}")

    credential = service["credential_source"]
    if credential is not None:
        credential = exact_map(credential, {"id", "service", "environment"}, "service.credential_source")
        credential_id = credential["id"]
        if (
            not isinstance(credential_id, str)
            or not 1 <= len(credential_id.encode("utf-8")) <= 128
            or CREDENTIAL_SOURCE_ID.fullmatch(credential_id) is None
        ):
            raise ContractError("credential source identity is invalid")
        if dns_name(credential["service"], "service.credential_source.service") != declared_name:
            raise ContractError("credential source is bound to another service")
        environment = credential["environment"]
        environment_name(environment, "service.credential_source.environment")


def validate_transcript(messages: object) -> None:
    _validate_transcript(messages, retained_only=False)


def validate_retained_transcript(messages: object) -> None:
    """Validate the retained install, installed, and release prefix.

    The transient credential value is intentionally absent. The release frame
    binds only its declared source and environment.
    """
    _validate_transcript(messages, retained_only=True)


def _validate_transcript(messages: object, *, retained_only: bool) -> None:
    admitted_lengths = {1, 2, 3} if retained_only else {3, 4}
    if not isinstance(messages, list) or len(messages) not in admitted_lengths:
        raise ContractError("launcher transcript does not have an admitted length")
    if any(not isinstance(message, dict) for message in messages):
        raise ContractError("launcher transcript contains a non-map message")
    schemas = [message.get("schema") for message in messages]
    without_credential = [
        "proofbound-runtime-service-launcher-install/1",
        "proofbound-runtime-service-launcher-boundary-installed/1",
        "proofbound-runtime-service-launcher-exec-release/1",
    ]
    with_credential = [
        "proofbound-runtime-service-launcher-install/1",
        "proofbound-runtime-service-launcher-boundary-installed/1",
        "proofbound-runtime-service-launcher-credential-release/1",
        "proofbound-runtime-service-launcher-exec-release/1",
    ]
    retained_install = without_credential[:1]
    retained_installed = without_credential[:2]
    if retained_only and schemas == retained_install:
        request_value = messages[0]
        installed_value = None
        release_value = None
        credential_value = None
    elif retained_only and schemas == retained_installed:
        request_value, installed_value = messages
        release_value = None
        credential_value = None
    elif schemas == without_credential:
        request_value, installed_value, release_value = messages
        credential_value = None
    elif schemas == with_credential:
        request_value, installed_value, credential_value, release_value = messages
    else:
        raise ContractError("launcher transcript messages are missing, duplicated, or out of order")
    for index, message in enumerate(messages):
        if len(encode(message)) > MAX_LAUNCHER_FRAME_BYTES:
            raise ContractError(f"launcher transcript frame {index} exceeds the transport bound")

    request = exact_map(
        request_value,
        {
            "schema", "execution_id", "policy_sha256", "cgroup", "executable",
            "executable_fd", "working_directory_fd", "arguments", "environment",
            "filesystem", "seccomp_program", "close_file_descriptors_from", "service",
        },
        "install request",
    )
    installed = None
    if installed_value is not None:
        installed = exact_map(
            installed_value,
            {"schema", "state", "execution_id", "policy_sha256", "cgroup", "install_request_sha256", "service"},
            "installed acknowledgement",
        )
    release = None
    if release_value is not None:
        release = exact_map(
            release_value,
            {"schema", "state", "execution_id", "policy_sha256", "cgroup", "install_request_sha256", "service_binding_sha256", "credential_state"},
            "exec release",
        )
    if request["schema"] != "proofbound-runtime-service-launcher-install/1":
        raise ContractError("install request has an unknown schema")
    if installed is not None and (installed["schema"] != "proofbound-runtime-service-launcher-boundary-installed/1" or installed["state"] != "installed"):
        raise ContractError("installed acknowledgement has an unknown schema or state")
    if release is not None and (release["schema"] != "proofbound-runtime-service-launcher-exec-release/1" or release["state"] != "released"):
        raise ContractError("exec release has an unknown schema or state")

    execution_id = bytes_exact(request["execution_id"], 16, "request.execution_id")
    policy = bytes_exact(request["policy_sha256"], 32, "request.policy_sha256")
    cgroup_id = cgroup(request["cgroup"], "request.cgroup")
    retained_messages = []
    if installed is not None:
        retained_messages.append(("installed", installed))
    if release is not None:
        retained_messages.append(("release", release))
    for context, message in retained_messages:
        if bytes_exact(message["execution_id"], 16, f"{context}.execution_id") != execution_id:
            raise ContractError(f"{context} execution identity changed")
        if bytes_exact(message["policy_sha256"], 32, f"{context}.policy_sha256") != policy:
            raise ContractError(f"{context} policy identity changed")
        if cgroup(message["cgroup"], f"{context}.cgroup") != cgroup_id:
            raise ContractError(f"{context} cgroup identity changed")

    artifact(request["executable"], "runtime-executable", "request.executable")
    executable_fd = integer(request["executable_fd"], 3, 2**31 - 1, "request.executable_fd")
    working_fd = integer(request["working_directory_fd"], 3, 2**31 - 1, "request.working_directory_fd")
    if (
        not isinstance(request["arguments"], list)
        or not 1 <= len(request["arguments"]) <= 4096
        or not all(isinstance(item, str) and "\0" not in item for item in request["arguments"])
    ):
        raise ContractError("request arguments are empty or invalid")
    if not isinstance(request["environment"], dict) or len(request["environment"]) > 4096:
        raise ContractError("request environment is not a map")
    for name, value in request["environment"].items():
        if not isinstance(value, str) or "\0" in value:
            raise ContractError("request environment entry is invalid")
        environment_name(name, "request.environment name")
    if not isinstance(request["filesystem"], list) or not 1 <= len(request["filesystem"]) <= 4096:
        raise ContractError("request filesystem is not an array")
    filesystem_fds = []
    filesystem_access = []
    access_rank = {"read": 0, "write": 1, "execute": 2}
    for index, rule_value in enumerate(request["filesystem"]):
        rule = exact_map(rule_value, {"fd", "access"}, f"request.filesystem[{index}]")
        filesystem_fds.append(integer(rule["fd"], 3, 2**31 - 1, f"request.filesystem[{index}].fd"))
        accesses = rule["access"]
        if (
            not isinstance(accesses, list)
            or not accesses
            or len(accesses) != len(set(accesses))
            or any(access not in access_rank for access in accesses)
            or accesses != sorted(accesses, key=access_rank.__getitem__)
        ):
            raise ContractError("filesystem access is empty, duplicate, or unknown")
        filesystem_access.append(accesses)
    if filesystem_fds != sorted(set(filesystem_fds)):
        raise ContractError("filesystem descriptors are not sorted and unique")
    try:
        executable_rule = filesystem_access[filesystem_fds.index(executable_fd)]
    except ValueError as error:
        raise ContractError("filesystem rules omit the executable descriptor") from error
    if executable_rule != ["read", "execute"]:
        raise ContractError("executable filesystem rule is not exact")
    seccomp_program = request["seccomp_program"]
    if not isinstance(seccomp_program, bytes) or not 1 <= len(seccomp_program) <= 1_048_576:
        raise ContractError("request seccomp program is empty")

    service_binding(request["service"])
    if installed is not None:
        service_binding(installed["service"])
        if installed["service"] != request["service"]:
            raise ContractError("installed acknowledgement changed the service binding")
    if hashlib.sha256(seccomp_program).digest() != request["service"]["child_filter_sha256"]:
        raise ContractError("child filter identity does not match the requested program")
    install_identity = hashlib.sha256(encode(request)).digest()
    if installed is not None and bytes_exact(installed["install_request_sha256"], 32, "installed.install_request_sha256") != install_identity:
        raise ContractError("installed acknowledgement changed the install request")
    if release is not None:
        if installed is None:
            raise ContractError("exec release has no installed acknowledgement")
        if bytes_exact(release["install_request_sha256"], 32, "release.install_request_sha256") != install_identity:
            raise ContractError("exec release changed the install request")
        if bytes_exact(release["service_binding_sha256"], 32, "release.service_binding_sha256") != hashlib.sha256(encode(request["service"])).digest():
            raise ContractError("exec release changed the service-binding identity")

    credential = request["service"]["credential_source"]
    binding_identity = hashlib.sha256(encode(request["service"])).digest()
    if credential is not None and credential["environment"] in request["environment"]:
        raise ContractError("credential value was present before boundary acknowledgement")
    if release is None:
        if credential_value is not None:
            raise ContractError("credential release has no exec release")
    elif credential is None:
        if credential_value is not None or release["credential_state"] != "not-declared":
            raise ContractError("undeclared credential entered the release handshake")
    elif retained_only:
        if credential_value is not None:
            raise ContractError("retained transcript contains a transient credential value")
        state = exact_map(release["credential_state"], {"state", "source_id", "environment"}, "release.credential_state")
        if state != {"state": "released", "source_id": credential["id"], "environment": credential["environment"]}:
            raise ContractError("exec release does not acknowledge the declared credential")
    else:
        message = exact_map(
            credential_value,
            {
                "schema", "execution_id", "policy_sha256", "cgroup",
                "install_request_sha256", "service_binding_sha256",
                "source_id", "environment", "value",
            },
            "credential release",
        )
        if message["schema"] != "proofbound-runtime-service-launcher-credential-release/1":
            raise ContractError("credential release has an unknown schema")
        if bytes_exact(message["execution_id"], 16, "credential.execution_id") != execution_id:
            raise ContractError("credential release changed execution identity")
        if bytes_exact(message["policy_sha256"], 32, "credential.policy_sha256") != policy:
            raise ContractError("credential release changed policy identity")
        if cgroup(message["cgroup"], "credential.cgroup") != cgroup_id:
            raise ContractError("credential release changed cgroup identity")
        if bytes_exact(message["install_request_sha256"], 32, "credential.install_request_sha256") != install_identity:
            raise ContractError("credential release changed the install request")
        if bytes_exact(message["service_binding_sha256"], 32, "credential.service_binding_sha256") != binding_identity:
            raise ContractError("credential release changed service binding")
        if message["source_id"] != credential["id"] or message["environment"] != credential["environment"]:
            raise ContractError("credential release changed its descriptor")
        transient_value = message["value"]
        if not isinstance(transient_value, bytes) or not 1 <= len(transient_value) <= 65_536:
            raise ContractError("credential release value is empty or exceeds its transient bound")
        state = exact_map(release["credential_state"], {"state", "source_id", "environment"}, "release.credential_state")
        if state != {"state": "released", "source_id": credential["id"], "environment": credential["environment"]}:
            raise ContractError("exec release does not acknowledge the declared credential")

    child_descriptor = request["service"]["channel"]["child_descriptor"]
    if executable_fd == working_fd or child_descriptor in {executable_fd, working_fd, *filesystem_fds}:
        raise ContractError("declared launcher descriptors overlap")
    retained_fds = [executable_fd, working_fd, child_descriptor, *filesystem_fds]
    close_from = integer(request["close_file_descriptors_from"], 3, 2**31 - 1, "request.close_file_descriptors_from")
    if any(descriptor >= close_from for descriptor in retained_fds):
        raise ContractError("a declared retained descriptor is inside the close range")

    forbidden = {"credential", "credential_value", "secret", "application_bytes", "request_bytes", "response_bytes"}
    stack = [request]
    if installed is not None:
        stack.append(installed)
    if release is not None:
        stack.append(release)
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            if forbidden.intersection(current):
                raise ContractError("launcher handshake contains secret or application content")
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
