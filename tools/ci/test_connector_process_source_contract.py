"""Independent mutation guards for the RT-5 connector process."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROCESS_SOURCE = (
    ROOT / "crates/proofbound-runtime-linux/src/connector_process.rs"
).read_text(encoding="utf-8")
SYS_SOURCE = (ROOT / "crates/proofbound-runtime-linux/src/sys.rs").read_text(
    encoding="utf-8"
)


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unclosed function: {signature}")


def implementation_body(source: str, signature: str) -> str:
    start = source.index(signature)
    return function_body(source[start:], signature)


def require_guards(body: str, guards: tuple[str, ...]) -> None:
    for guard in guards:
        if guard not in body:
            raise AssertionError(f"missing production guard: {guard}")


def require_causal_guards(body: str, guards: tuple[str, ...]) -> None:
    require_guards(body, guards)
    for guard in guards:
        with unittest.TestCase().assertRaises(AssertionError):
            require_guards(body.replace(guard, "", 1), guards)


def ordered_positions(body: str, guards: tuple[str, ...]) -> tuple[int, ...]:
    positions = []
    cursor = 0
    for guard in guards:
        position = body.find(guard, cursor)
        if position == -1:
            raise AssertionError(f"required production order absent: {guards!r}")
        positions.append(position)
        cursor = position + len(guard)
    return tuple(positions)


def require_order(body: str, guards: tuple[str, ...]) -> None:
    ordered_positions(body, guards)


def require_causal_order(body: str, guards: tuple[str, ...]) -> None:
    positions = ordered_positions(body, guards)
    for position, guard in zip(positions, guards, strict=True):
        mutated = body[:position] + body[position + len(guard) :]
        with unittest.TestCase().assertRaises(AssertionError):
            require_order(mutated, guards)
    for index in range(len(guards) - 1):
        left = guards[index]
        right = guards[index + 1]
        left_start = positions[index]
        right_start = positions[index + 1]
        middle = body[left_start + len(left) : right_start]
        mutated = (
            body[:left_start]
            + right
            + middle
            + left
            + body[right_start + len(right) :]
        )
        with unittest.TestCase().assertRaises(AssertionError):
            require_order(mutated, guards)


class ConnectorProcessSourceContractTests(unittest.TestCase):
    def test_artifact_preparation_revalidates_every_declared_identity_and_path(self) -> None:
        body = function_body(PROCESS_SOURCE, "pub fn prepare_connector_process")
        guards = (
            "connector.revalidate_identity()?;",
            "plan_source.revalidate_identity().map_err(map_resolution)?;",
            "trust_root.revalidate_identity()?;",
            "resolver_configuration.revalidate_identity()?;",
            "artifact.revalidate_identity()?;",
            "connector.read_bytes(MAX_CONNECTOR_EXECUTABLE_BYTES)?",
            "parse_elf_interpreter(&connector_bytes, architecture)",
            ".find(|artifact| artifact.requested_path() == interpreter.as_path())",
            "loader.identity().mode().get() & 0o111 == 0",
            "plan_source.identity().size() > MAX_PLAN_BYTES",
            "validate_declared_artifacts(",
            "digest_runtime_closure(runtime_closure)",
        )
        require_causal_guards(body, guards)
        require_causal_order(
            body,
            (
                "let plan = parse_service_execution_plan(&plan_bytes)",
                "let setup_deadline = Instant::now()",
                "connector.revalidate_identity()?;",
                "let connector_bytes = connector.read_bytes(MAX_CONNECTOR_EXECUTABLE_BYTES)?;",
                "validate_declared_artifacts(",
                "let runtime_closure_digest = digest_runtime_closure(runtime_closure);",
                "Ok(PreparedConnectorProcess {",
            ),
        )
        self.assertGreaterEqual(body.count("require_before_deadline(setup_deadline)?;"), 8)
        self.assertIn("setup_deadline,", body)

        binding = function_body(PROCESS_SOURCE, "fn validate_declared_artifacts")
        require_causal_guards(
            binding,
            (
                "session.connector_executable().as_str()",
                "session.tls().trust_root_set().as_str()",
                "session.resolution().configuration().as_str()",
                "runtime_closure.len() != session.connector_runtime_read().len()",
                ".zip(session.connector_runtime_read())",
            ),
        )

    def test_bootstrap_parser_has_exact_vocabulary_and_unique_descriptors(self) -> None:
        body = function_body(PROCESS_SOURCE, "pub fn parse_connector_bootstrap")
        guards = (
            "arguments.len() != CONNECTOR_BOOTSTRAP_ARGUMENTS",
            '"--connector-protocol"',
            '"--plan-fd"',
            '"--trust-root-fd"',
            '"--channel-fd"',
            '"--control-fd"',
            '"--execution-id"',
            '"--policy-sha256"',
            '"--process-generation"',
            '"--channel-id"',
            '"--plan-sha256"',
            '"--trust-root-sha256"',
            '"--connector-sha256"',
            '"--runtime-closure-sha256"',
            '"--resolver-configuration-sha256"',
            "ConnectorProcessGeneration::new(",
            "ServiceChannelId::new(parse_hex_array(&arguments[17])?)",
            "descriptors.windows(2).any(|pair| pair[0] == pair[1])",
        )
        require_causal_guards(body, guards)

    def test_spawn_creates_private_channels_and_waits_for_bound_ready(self) -> None:
        body = implementation_body(PROCESS_SOURCE, "pub fn spawn(self)")
        guards = (
            "let setup_deadline = self.setup_deadline;",
            "let reaper = connector_reaper_sender()?;",
            "crate::sys::private_socket_pair()",
            "crate::sys::private_stream_pair()",
            "crate::sys::inherit_only_descriptors_for_exec(",
            ".env_clear()",
            "let packet = process.receive_before(setup_deadline)?;",
            "process.reap_before(false, setup_deadline)?;",
            "let terminal_deadline = Instant::now()",
            "ConnectorReport::Ready(ready)",
            "require_ready_binding(",
            "setup_binding_digest(",
            "ConnectorReport::Failure(failure)",
        )
        require_causal_guards(body, guards)
        self.assertGreaterEqual(body.count("require_before_deadline(setup_deadline)?;"), 6)
        require_causal_order(
            body,
            (
                "let setup_deadline = self.setup_deadline;",
                "let reaper = connector_reaper_sender()?;",
                "self.connector.revalidate_identity()?;",
                "command.spawn()",
                "let packet = process.receive_before(setup_deadline)?;",
                "require_ready_binding(",
                "require_before_deadline(setup_deadline)?;",
                "let channel = UnixStream::from(child_channel);",
            ),
        )
        self.assertIn("reaper,", body)

        stream_pair = function_body(SYS_SOURCE, "pub(crate) fn private_stream_pair")
        require_causal_guards(
            stream_pair,
            (
                "libc::AF_UNIX",
                "libc::SOCK_STREAM | libc::SOCK_CLOEXEC",
                "OwnedFd::from_raw_fd(descriptors[0])",
                "OwnedFd::from_raw_fd(descriptors[1])",
            ),
        )
        inheritance = function_body(
            SYS_SOURCE, "pub(crate) fn inherit_only_descriptors_for_exec"
        )
        require_causal_guards(
            inheritance,
            (
                "inherited_descriptors.sort_unstable();",
                "let mut retained_descriptors = inherited_descriptors.clone();",
                "retained_descriptors.extend(transient_exec_descriptors.iter().copied());",
                "retained_descriptors.sort_unstable();",
                "close_descriptor_range(first, descriptor - 1)?;",
                "close_descriptor_range(first, u32::MAX)?;",
                "for descriptor in &inherited_descriptors",
                "libc::fcntl(*descriptor, libc::F_SETFD, 0)",
                "for descriptor in &transient_exec_descriptors",
                "libc::fcntl(*descriptor, libc::F_SETFD, libc::FD_CLOEXEC)",
            ),
        )

    def test_connector_verifies_artifacts_and_reports_ready_before_proxy(self) -> None:
        body = function_body(PROCESS_SOURCE, "pub fn run_connector_process")
        guards = (
            "let control_fd = take_inherited(bootstrap.control_descriptor)?;",
            "read_inherited_file(File::from(plan_fd), MAX_PLAN_BYTES)",
            "read_inherited_file(File::from(trust_fd), MAX_TRUST_ROOT_BYTES)",
            "digest_bytes(&plan_bytes) != bootstrap.plan_digest",
            "digest_bytes(&trust_root_bytes) != bootstrap.trust_root_digest",
            "parse_service_execution_plan(&plan_bytes)",
            "proofbound_runtime_connector::resolve_service(plan.service_session())",
            "proofbound_runtime_connector::authenticate_service(",
            "crate::sys::send_packet(control_fd.as_raw_fd(), &encode_ready(ready))",
            "proofbound_runtime_connector::proxy_authenticated_channel(session, channel)",
            "crate::sys::send_packet(control_fd.as_raw_fd(), &encode_terminal(terminal))",
        )
        require_causal_guards(body, guards)
        ordered = tuple(
            body.index(guard)
            for guard in (
                "proofbound_runtime_connector::resolve_service(plan.service_session())",
                "proofbound_runtime_connector::authenticate_service(",
                "crate::sys::send_packet(control_fd.as_raw_fd(), &encode_ready(ready))",
                "proofbound_runtime_connector::proxy_authenticated_channel(session, channel)",
                "crate::sys::send_packet(control_fd.as_raw_fd(), &encode_terminal(terminal))",
            )
        )
        self.assertEqual(ordered, tuple(sorted(ordered)))
        self.assertNotIn("Credential", body)
        self.assertNotIn("std::env", body)

    def test_process_guard_has_bounded_wait_and_terminal_kill_reap(self) -> None:
        terminal = function_body(PROCESS_SOURCE, "fn validate_terminal")
        require_causal_guards(
            terminal,
            (
                "terminal.child_to_service_bytes > child_to_service_limit",
                "terminal.service_to_child_bytes > service_to_child_limit",
                "terminal.active_ns != ready.authenticated_ns",
                "terminal.closed_ns < terminal.active_ns",
            ),
        )
        finish = function_body(PROCESS_SOURCE, "pub fn finish(mut self)")
        require_causal_guards(
            finish,
            (
                "self.process.receive_before(self.terminal_deadline)?",
                "self.process.reap_before(true, self.terminal_deadline)?;",
                "self.process.reap_before(false, self.terminal_deadline)?;",
            ),
        )
        require_causal_order(
            finish,
            (
                "self.process.receive_before(self.terminal_deadline)?",
                "self.process.reap_before(true, self.terminal_deadline)?;",
                "validate_terminal(",
                "require_before_deadline(self.terminal_deadline)?;",
                "Ok(terminal)",
            ),
        )

        receive = function_body(PROCESS_SOURCE, "fn receive_before")
        require_causal_order(
            receive,
            (
                "crate::sys::wait_readable(descriptor, timeout)",
                "crate::sys::receive_packet(descriptor, &mut buffer)",
                "require_before_deadline(deadline)?;",
                "Ok(buffer[..length].to_vec())",
            ),
        )
        reap = function_body(PROCESS_SOURCE, "fn reap_before")
        require_causal_guards(
            reap,
            (
                ".try_wait()",
                "remaining.min(Duration::from_millis(1))",
                "status.success() == expected_success",
            ),
        )
        self.assertNotIn("checked_add", reap)
        self.assertGreaterEqual(reap.count("require_before_deadline(deadline)?;"), 2)
        require_causal_order(
            reap,
            (
                "require_before_deadline(deadline)?;",
                ".try_wait()",
                "require_before_deadline(deadline)?;",
                "if let Some(status) = status",
            ),
        )

        cleanup = function_body(PROCESS_SOURCE, "fn terminate_without_blocking")
        require_causal_guards(
            cleanup,
            (
                "self.control.take();",
                "self.child.take()",
                "child.kill()",
                "self.reaper.send(child).is_err()",
                "std::process::abort()",
            ),
        )
        reaper = function_body(PROCESS_SOURCE, "fn connector_reaper_sender")
        require_causal_guards(
            reaper,
            (
                "OnceLock<Option<mpsc::Sender<std::process::Child>>>",
                "mpsc::channel::<std::process::Child>()",
                'std::thread::Builder::new()',
                '.name("pbr-connector-reaper".to_owned())',
                "while let Ok(mut child) = receiver.recv()",
                "child.wait()",
                ".ok()",
                ".ok_or(ConnectorProcessError::ReaperUnavailable)",
            ),
        )
        drop_body = implementation_body(PROCESS_SOURCE, "impl Drop for ConnectorProcessGuard")
        require_causal_guards(drop_body, ("self.terminate_without_blocking();",))
        self.assertNotIn(".wait()", drop_body)

        remaining = function_body(PROCESS_SOURCE, "fn remaining_before")
        require_causal_guards(
            remaining,
            (
                ".checked_duration_since(Instant::now())",
                ".filter(|remaining| !remaining.is_zero())",
                ".ok_or(ConnectorProcessError::Timeout)",
            ),
        )


if __name__ == "__main__":
    unittest.main()
