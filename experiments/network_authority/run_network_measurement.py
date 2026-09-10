#!/usr/bin/env python3
"""Run one native mechanism measurement for experiment 0001I."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.measurement_domain import (
    ARCHITECTURES,
    MAXIMUM_SECONDS,
    MECHANISMS,
    MeasurementDomainError,
    load_measurement_domain,
)
from experiments.network_authority.measurement_observation import (
    MeasurementObservationError,
    lifecycle_observation,
    summarize_samples,
)
from experiments.network_authority.record_common import (
    SOURCE_COMMIT,
    RecordError,
    canonical_json,
    regular_bytes,
    sha256,
    write_new,
)
from experiments.network_authority.routing_cell import RoutingCellError, classify
from experiments.network_authority.routing_mediator import open_authenticated
from experiments.network_authority.routing_transport_case import load_routing_matrix
from experiments.network_authority.run_routing_direct_case import (
    FixturePlan,
    read_document,
    reap_fixture,
)
from experiments.network_authority.run_routing_preconnected_case import start_fixture


MAX_PROCESS_OUTPUT = 65536
MAX_STATE_FILES = 32
MAX_STATE_BYTES = 1024 * 1024
EXACT_CASE = "exact-service-ipv4"
SETUP_STATE_NAMES = {
    "landlock-port": {
        "boundary-observations.txt",
        "ruleset-configuration.txt",
    },
    "cgroup-endpoint": {
        "boundary-observations.txt",
        "connect4-map-key.bin",
        "connect4-program.bin",
        "connect4-verifier.log",
        "connect6-map-key.bin",
        "connect6-program.bin",
        "connect6-verifier.log",
        "map-value.bin",
    },
}


class MeasurementRunError(Exception):
    """The native measurement did not produce one complete raw observation."""


def deadline_expired(_signum: int, _frame: object) -> None:
    """Abort a measurement that exceeds its pre-registered wall-clock bound."""

    raise MeasurementRunError("network measurement exceeded 600 seconds")


def run_bounded(arguments: argparse.Namespace) -> Path:
    """Run one measurement within the frozen total wall-clock bound."""

    previous = signal.signal(signal.SIGALRM, deadline_expired)
    signal.alarm(MAXIMUM_SECONDS)
    try:
        return run(arguments)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def clock_identity() -> tuple[int, str]:
    """Select the pre-registered monotonic clock."""

    if hasattr(time, "CLOCK_MONOTONIC_RAW"):
        return time.CLOCK_MONOTONIC_RAW, "CLOCK_MONOTONIC_RAW"
    return time.CLOCK_MONOTONIC, "CLOCK_MONOTONIC"


def now_ns(clock: int) -> int:
    """Read one integer nanosecond value from the selected clock."""

    value = time.clock_gettime_ns(clock)
    if type(value) is not int or value <= 0:
        raise MeasurementRunError("monotonic clock observation is invalid")
    return value


def bounded_process(command: list[str], root: Path, timeout: int = 10) -> subprocess.CompletedProcess[bytes]:
    """Run one closed command and retain bounded diagnostic bytes."""

    completed = subprocess.run(
        command,
        cwd=root,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if len(completed.stdout) > MAX_PROCESS_OUTPUT or len(completed.stderr) > MAX_PROCESS_OUTPUT:
        raise MeasurementRunError("measurement process output exceeded its bound")
    return completed


def process_failure_diagnostic(completed: subprocess.CompletedProcess[bytes]) -> str:
    """Retain exact bounded child output in an ASCII failure diagnostic."""

    return canonical_json({
        "returncode": completed.returncode,
        "schema": "proofbound-runtime-network-measurement-process-failure/1",
        "stderr_base64": base64.b64encode(completed.stderr).decode("ascii"),
        "stderr_sha256": sha256(completed.stderr),
        "stdout_base64": base64.b64encode(completed.stdout).decode("ascii"),
        "stdout_sha256": sha256(completed.stdout),
    }).decode("ascii").rstrip("\n")


def tree_summary(root: Path) -> dict[str, object]:
    """Identify every bounded regular file below one mechanism state root."""

    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise MeasurementRunError("measurement state root is invalid")
    entries = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            raise MeasurementRunError("measurement state contains a non-regular entry")
        data = regular_bytes(path)
        total += len(data)
        entries.append(
            {
                "name": path.relative_to(root).as_posix(),
                "sha256": sha256(data),
                "size_bytes": len(data),
            }
        )
        if len(entries) > MAX_STATE_FILES or total > MAX_STATE_BYTES:
            raise MeasurementRunError("measurement state exceeds its bound")
    if not entries:
        raise MeasurementRunError("measurement state is empty")
    identity = sha256(canonical_json(entries))
    return {
        "file_count": len(entries),
        "files": entries,
        "sha256": identity,
        "total_bytes": total,
    }


def remove_state(path: Path) -> bool:
    """Remove one exact temporary state directory and report absence."""

    try:
        shutil.rmtree(path)
    except OSError:
        return False
    return not path.exists() and not path.is_symlink()


def direct_command(arguments: argparse.Namespace, state: Path, cgroup: Path | None, failure: bool) -> list[str]:
    """Build one direct mechanism setup or forced-failure command."""

    # Use one executable with one stable exit status for both direct controls.
    # A missing executable is not a portable wrapper-level failure: the
    # Landlock control reports its own exec failure while the endpoint control
    # faithfully returns the forked child's 127.  /bin/false instead proves
    # the installed boundary released no request and leaves cleanup semantics
    # independent of each wrapper's exec-error convention.
    child = "/bin/false" if failure else "/bin/true"
    if arguments.mechanism == "landlock-port":
        return [str(arguments.landlock_control), "443", str(state), "--", child]
    if arguments.mechanism == "cgroup-endpoint" and cgroup is not None:
        return [
            str(arguments.endpoint_control),
            str(cgroup),
            "127.0.0.1",
            "fd00::1",
            "443",
            str(state),
            "--",
            child,
        ]
    raise MeasurementRunError("direct setup mechanism is invalid")


def run_direct_setup(
    arguments: argparse.Namespace,
    scratch: Path,
    index: int,
    clock: int,
    failure: bool,
    retain_reference: Path | None = None,
) -> dict[str, object]:
    """Create, observe, and remove one Landlock or cgroup-BPF boundary."""

    state = scratch / f"state-{index:04d}"
    cgroup = None
    started = now_ns(clock)
    try:
        if arguments.mechanism == "cgroup-endpoint":
            if arguments.cgroup_parent is None:
                raise MeasurementRunError("endpoint setup lacks a cgroup parent")
            cgroup = arguments.cgroup_parent / f"proofbound-measure-{os.getpid()}-{index}"
            cgroup.mkdir(mode=0o755)
        completed = bounded_process(
            direct_command(arguments, state, cgroup, failure), arguments.source_root
        )
        expected_exit = 1 if failure else 0
        if completed.returncode != expected_exit:
            raise MeasurementRunError("direct setup exit changed")
        if {path.name for path in state.iterdir()} != SETUP_STATE_NAMES[arguments.mechanism]:
            raise MeasurementRunError("direct setup state inventory changed")
        summary = tree_summary(state)
        if retain_reference is not None:
            shutil.copytree(state, retain_reference)
        cleanup = remove_state(state)
        if cgroup is not None:
            try:
                cgroup.rmdir()
            except OSError:
                cleanup = False
        completed_ns = now_ns(clock)
        if not cleanup:
            raise MeasurementRunError("direct setup cleanup failed")
        return {
            "cleanup": True,
            "duration_ns": completed_ns - started,
            "exit": completed.returncode,
            "iteration": index,
            "state": summary,
        }
    finally:
        if state.exists() and state.is_dir() and not state.is_symlink():
            shutil.rmtree(state, ignore_errors=True)
        if cgroup is not None and cgroup.exists():
            try:
                cgroup.rmdir()
            except OSError:
                pass


def broker_setup_command(arguments: argparse.Namespace, descriptor: int, root: Path) -> list[str]:
    """Build one real broker process that publishes readiness before input."""

    return [
        sys.executable,
        "-m",
        "experiments.network_authority.routing_mediator",
        "--fd",
        str(descriptor),
        "--dial-address",
        "127.0.0.1",
        "--expected-address",
        "127.0.0.1",
        "--port",
        "443",
        "--ca-certificate",
        str(arguments.allowed_certificate),
        "--marker",
        str(root / "mediator.json"),
        "--session-observation",
        str(root / "session.json"),
        "--ready",
        str(root / "ready.json"),
    ]


def wait_ready(path: Path, process: subprocess.Popen[bytes]) -> None:
    """Wait at most two seconds for one no-replace readiness marker."""

    for _ in range(200):
        if path.is_file():
            value = read_document(path)
            if value != {
                "schema": "proofbound-runtime-routing-mediator-ready/1",
                "state": "waiting-for-operation",
            }:
                raise MeasurementRunError("broker readiness marker changed")
            return
        if process.poll() is not None:
            break
        time.sleep(0.01)
    raise MeasurementRunError("broker did not publish readiness")


def run_broker_setup(
    arguments: argparse.Namespace,
    scratch: Path,
    index: int,
    clock: int,
    retain_reference: Path | None = None,
) -> dict[str, object]:
    """Create a broker and channel, then inject EOF before any request."""

    root = scratch / f"broker-{index:04d}"
    root.mkdir(mode=0o755)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    process = None
    started = now_ns(clock)
    try:
        process = subprocess.Popen(
            broker_setup_command(arguments, parent.fileno(), root),
            cwd=arguments.source_root,
            env={
                "PATH": "/usr/bin:/bin",
                "PYTHONHASHSEED": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            pass_fds=(parent.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        parent.close()
        wait_ready(root / "ready.json", process)
        child.close()
        if process.wait(timeout=2) != 4:
            raise MeasurementRunError("broker failure injection exit changed")
        summary = tree_summary(root)
        if retain_reference is not None:
            shutil.copytree(root, retain_reference)
        cleanup = remove_state(root)
        completed_ns = now_ns(clock)
        if not cleanup or process.poll() is None:
            raise MeasurementRunError("broker setup cleanup failed")
        return {
            "cleanup": True,
            "duration_ns": completed_ns - started,
            "exit": 4,
            "iteration": index,
            "state": summary,
        }
    finally:
        parent.close()
        child.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        if root.exists() and root.is_dir() and not root.is_symlink():
            shutil.rmtree(root, ignore_errors=True)


def run_preconnected_setup(
    arguments: argparse.Namespace,
    scratch: Path,
    index: int,
    clock: int,
    retain_reference: Path | None = None,
) -> dict[str, object]:
    """Authenticate one connector session, then fail before child release."""

    root = scratch / f"connector-{index:04d}"
    fixture_arguments = argparse.Namespace(
        repository_root=arguments.source_root,
        case_root=root,
        allowed_certificate=arguments.allowed_certificate,
        allowed_private_key=arguments.allowed_private_key,
        denied_certificate=arguments.denied_certificate,
        denied_private_key=arguments.denied_private_key,
    )
    fixture = start_fixture(
        FixturePlan(
            "experiments.network_authority.decision_http_fixture",
            "127.0.0.1",
            443,
            "exact",
            "allowed",
        ),
        fixture_arguments,
        root,
    )
    protected = None
    parent = None
    child = None
    started = now_ns(clock)
    try:
        protected, session = open_authenticated(
            "127.0.0.1", "127.0.0.1", 443, arguments.allowed_certificate
        )
        write_new(root / "session-observation.json", canonical_json(session))
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        child.close()
        child = None
        parent.close()
        parent = None
        protected.close()
        protected = None
        cleanup = reap_fixture(fixture.process, True)
        fixture.close_streams()
        summary = tree_summary(root)
        if retain_reference is not None:
            shutil.copytree(root, retain_reference)
        cleanup = remove_state(root) and cleanup
        completed_ns = now_ns(clock)
        if not cleanup:
            raise MeasurementRunError("connector setup cleanup failed")
        return {
            "cleanup": True,
            "duration_ns": completed_ns - started,
            "exit": 0,
            "iteration": index,
            "state": summary,
        }
    finally:
        for channel in (parent, child, protected):
            if channel is not None:
                channel.close()
        if fixture.process.poll() is None:
            fixture.process.kill()
            fixture.process.wait(timeout=2)
        try:
            fixture.close_streams()
        except OSError:
            pass
        if root.exists() and root.is_dir() and not root.is_symlink():
            shutil.rmtree(root, ignore_errors=True)


def request_command(arguments: argparse.Namespace, case_root: Path, cgroup: Path | None) -> list[str]:
    """Build the existing exact functional case command for one mechanism."""

    common = [
        "--case", EXACT_CASE,
        "--repository-root", str(arguments.source_root),
        "--matrix", str(arguments.matrix),
        "--case-root", str(case_root),
        "--raw-output", str(case_root / "raw-cell.json"),
        "--client", str(arguments.client),
        "--allowed-certificate", str(arguments.allowed_certificate),
        "--allowed-private-key", str(arguments.allowed_private_key),
        "--denied-certificate", str(arguments.denied_certificate),
        "--denied-private-key", str(arguments.denied_private_key),
    ]
    if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
        control = (
            arguments.landlock_control
            if arguments.mechanism == "landlock-port"
            else arguments.endpoint_control
        )
        command = [
            sys.executable,
            "-m",
            "experiments.network_authority.run_routing_direct_case",
            "--mechanism",
            arguments.mechanism,
            "--mechanism-control",
            str(control),
            "--child-control",
            str(arguments.routing_child_control),
            *common,
        ]
        if cgroup is not None:
            command.extend(["--cgroup-directory", str(cgroup)])
        return command
    if arguments.mechanism == "explicit-broker":
        return [
            sys.executable,
            "-m",
            "experiments.network_authority.run_routing_broker_case",
            "--child-control",
            str(arguments.broker_child_control),
            "--mediator-resource-output",
            str(case_root / "mediator-resource.json"),
            *common,
        ]
    if arguments.mechanism == "preconnected-channel":
        return [
            sys.executable,
            "-m",
            "experiments.network_authority.run_routing_preconnected_case",
            "--child-control",
            str(arguments.preconnected_child_control),
            *common,
        ]
    raise MeasurementRunError("request mechanism is invalid")


def run_request(
    arguments: argparse.Namespace,
    request_root: Path,
    index: int,
    clock: int,
    exact_case: object,
) -> tuple[dict[str, object], int | None]:
    """Run and classify one exact functional request without reading its expectation."""

    case_root = request_root / f"{index:03d}"
    cgroup = None
    started = now_ns(clock)
    if arguments.mechanism == "cgroup-endpoint":
        if arguments.cgroup_parent is None:
            raise MeasurementRunError("endpoint request lacks a cgroup parent")
        cgroup = arguments.cgroup_parent / f"proofbound-measure-request-{os.getpid()}-{index}"
        cgroup.mkdir(mode=0o755)
    try:
        completed = bounded_process(
            request_command(arguments, case_root, cgroup),
            arguments.source_root,
            timeout=20,
        )
        completed_ns = now_ns(clock)
        if completed.returncode != 0:
            raise MeasurementRunError(
                "exact request runner failed: "
                f"{process_failure_diagnostic(completed)}"
            )
        raw = read_document(case_root / "raw-cell.json")
        try:
            observed = classify(  # type: ignore[arg-type]
                raw, exact_case, arguments.mechanism
            )
        except RoutingCellError as error:
            raw_diagnostic = canonical_json(raw).decode("ascii").rstrip("\n")
            raise MeasurementRunError(
                f"exact request classification failed: {error}; raw={raw_diagnostic}"
            ) from error
        if observed.outcome != "allowed" or observed.stage != "application-protocol":
            raise MeasurementRunError("exact request classification changed")
        fixture = read_document(case_root / "fixture-observation.json")
        if (
            fixture.get("event") != "exact-response"
            or fixture.get("sni") != "allowed.test"
            or fixture.get("tls_version") != "TLSv1.3"
        ):
            raise MeasurementRunError("exact request fixture observation changed")
        maximum_rss = None
        if arguments.mechanism == "explicit-broker":
            mediator = read_document(case_root / "mediator-resource.json")
            if (
                mediator.get("schema")
                != "proofbound-runtime-routing-mediator-resource/1"
                or mediator.get("maximum_process_count") != 1
                or type(mediator.get("maximum_resident_set_bytes")) is not int
            ):
                raise MeasurementRunError("broker resource observation changed")
            maximum_rss = int(mediator["maximum_resident_set_bytes"])
        return (
            {
                "duration_ns": completed_ns - started,
                "iteration": index,
                "raw_cell_sha256": sha256(regular_bytes(case_root / "raw-cell.json")),
            },
            maximum_rss,
        )
    finally:
        if cgroup is not None and cgroup.exists():
            try:
                cgroup.rmdir()
            except OSError as error:
                raise MeasurementRunError("request cgroup survived cleanup") from error


def read_effective_capabilities() -> str:
    """Read the exact effective Linux capability mask."""

    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("CapEff:\t"):
            value = line.split("\t", 1)[1]
            if re.fullmatch(r"[0-9a-f]{16}", value):
                return value
    raise MeasurementRunError("effective capability observation is unavailable")


def read_controllers() -> list[str]:
    """Read the sorted cgroup v2 controller inventory."""

    path = Path("/sys/fs/cgroup/cgroup.controllers")
    if not path.is_file() or path.is_symlink():
        raise MeasurementRunError("cgroup v2 controller inventory is unavailable")
    values = path.read_text(encoding="ascii").split()
    if not values or len(values) != len(set(values)):
        raise MeasurementRunError("cgroup controller inventory is invalid")
    return sorted(values)


def landlock_abi(arguments: argparse.Namespace) -> int | None:
    """Read the native Landlock ABI when the mechanism requires it."""

    if arguments.mechanism != "landlock-port":
        return None
    completed = bounded_process(
        [str(arguments.landlock_control), "--print-abi"], arguments.source_root
    )
    try:
        value = int(completed.stdout.strip())
    except ValueError as error:
        raise MeasurementRunError("Landlock ABI observation is invalid") from error
    if completed.returncode != 0 or value < 4:
        raise MeasurementRunError("required Landlock ABI is unavailable")
    return value


def self_maximum_rss_bytes() -> int:
    """Return the current process resident-set high-water mark on Linux."""

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if value <= 0:
        raise MeasurementRunError("connector resident-set observation is invalid")
    return value * 1024


def setup_sample(
    arguments: argparse.Namespace,
    scratch: Path,
    index: int,
    clock: int,
    reference: Path | None,
) -> dict[str, object]:
    """Dispatch one cold setup sample through the selected real mechanism."""

    if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
        return run_direct_setup(arguments, scratch, index, clock, False, reference)
    if arguments.mechanism == "explicit-broker":
        return run_broker_setup(arguments, scratch, index, clock, reference)
    return run_preconnected_setup(arguments, scratch, index, clock, reference)


def lifecycle_trial(
    arguments: argparse.Namespace, scratch: Path, index: int, clock: int
) -> tuple[str | None, str | None]:
    """Run one forced pre-request failure and retain its bounded diagnostic."""

    try:
        if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
            result = run_direct_setup(arguments, scratch, index, clock, True)
            if result["exit"] != 4:
                return "failure-injection-failed"
        elif arguments.mechanism == "explicit-broker":
            result = run_broker_setup(arguments, scratch, index, clock)
            if result["exit"] != 4:
                return "failure-injection-failed"
        else:
            result = run_preconnected_setup(arguments, scratch, index, clock)
        if result["cleanup"] is not True:
            return "cleanup-failed", "lifecycle result reported incomplete cleanup"
        return None, None
    except FileExistsError as error:
        return "create-failed", f"{type(error).__name__}: {error}"
    except (MeasurementRunError, OSError, subprocess.SubprocessError) as error:
        return "observation-invalid", f"{type(error).__name__}: {error}"


def run(arguments: argparse.Namespace) -> Path:
    """Execute and publish one complete raw measurement observation."""

    if os.geteuid() != 0 or platform.system() != "Linux":
        raise MeasurementRunError("network measurement requires root on native Linux")
    if (
        arguments.mechanism not in MECHANISMS
        or not SOURCE_COMMIT.fullmatch(arguments.source_commit)
        or platform.machine() not in ARCHITECTURES
    ):
        raise MeasurementRunError("network measurement identity is invalid")
    domain = load_measurement_domain(arguments.domain)
    profile = domain.profile(arguments.mechanism)
    matrix = load_routing_matrix(arguments.matrix)
    exact = [case for case in matrix.cases if case.identifier == EXACT_CASE]
    if len(exact) != 1:
        raise MeasurementRunError("exact request case is not unique")
    if arguments.observation_root.exists() or not arguments.observation_root.parent.is_dir():
        raise MeasurementRunError("measurement observation root must be absent")
    arguments.observation_root.mkdir(mode=0o755)
    requests = arguments.observation_root / "requests"
    scratch = arguments.observation_root / "scratch"
    requests.mkdir(mode=0o755)
    scratch.mkdir(mode=0o755)
    reference = arguments.observation_root / "reference-setup-state"
    clock, clock_name = clock_identity()

    setup = [
        setup_sample(arguments, scratch, index, clock, reference if index == 0 else None)
        for index in range(100)
    ]
    request_values = []
    mediator_rss = []
    for index in range(100):
        observed, maximum_rss = run_request(
            arguments, requests, index, clock, exact[0]
        )
        request_values.append(observed)
        if maximum_rss is not None:
            mediator_rss.append(maximum_rss)
    trials = [
        lifecycle_trial(arguments, scratch, index, clock) for index in range(1000)
    ]
    outcomes = [outcome for outcome, _diagnostic in trials]
    lifecycle = lifecycle_observation(outcomes, 1000)
    if lifecycle["passed_count"] != 1000:
        first = lifecycle["first_failure"]
        if not isinstance(first, dict):
            raise MeasurementRunError("lifecycle failure identity is absent")
        iteration = first["iteration"]
        diagnostic = trials[iteration][1]
        if diagnostic is None or len(diagnostic.encode("utf-8")) > 1024:
            diagnostic = "bounded lifecycle diagnostic unavailable"
        raise MeasurementRunError(
            "one or more lifecycle trials failed: "
            f"code={first['code']} iteration={iteration} detail={diagnostic}"
        )

    shutil.rmtree(scratch)
    setup_summary = summarize_samples(
        (int(item["duration_ns"]) for item in setup), 100
    )
    request_summary = summarize_samples(
        (int(item["duration_ns"]) for item in request_values), 100
    )
    maximum_rss = None
    maximum_process_count = None
    if profile.mediator_metrics:
        maximum_process_count = 1
        maximum_rss = (
            max(mediator_rss)
            if arguments.mechanism == "explicit-broker"
            else self_maximum_rss_bytes()
        )
    platform_observation = {
        "architecture": platform.machine(),
        "bpf_features": list(profile.required_mechanism_features)
        if arguments.mechanism == "cgroup-endpoint"
        else [],
        "cgroup_v2_controllers": read_controllers(),
        "effective_capabilities": read_effective_capabilities(),
        "kernel_release": platform.release(),
        "landlock_abi": landlock_abi(arguments),
        "monotonic_clock": clock_name,
        "namespace_operations": ["mount", "network"],
        "python": platform.python_version(),
        "schema": "proofbound-runtime-network-measurement-platform/1",
        "tls_implementation": ssl.OPENSSL_VERSION,
    }
    raw = {
        "decision_matrix_sha256": matrix.source_sha256,
        "lifecycle": lifecycle,
        "measurement_domain_sha256": domain.source_sha256,
        "mechanism": arguments.mechanism,
        "mediator_resources": {
            "maximum_process_count": maximum_process_count,
            "maximum_resident_set_bytes": maximum_rss,
        },
        "platform": platform_observation,
        "request_observations": request_values,
        "request_summary": request_summary,
        "residual_authority": list(profile.expected_residual_authority),
        "schema": "proofbound-runtime-network-raw-measurement/1",
        "setup_observations": setup,
        "setup_summary": setup_summary,
        "source_commit": arguments.source_commit,
    }
    write_new(arguments.observation_root / "RAW.json", canonical_json(raw))
    return arguments.observation_root


def parser() -> argparse.ArgumentParser:
    """Build the closed network measurement runner interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--mechanism", choices=MECHANISMS, required=True)
    for name in (
        "source-root", "domain", "matrix", "observation-root",
        "landlock-control", "endpoint-control", "routing-child-control",
        "broker-child-control", "preconnected-child-control", "client",
        "allowed-certificate", "allowed-private-key", "denied-certificate",
        "denied-private-key", "cgroup-parent",
    ):
        result.add_argument(f"--{name}", type=Path)
    result.add_argument("--source-commit", required=True)
    return result


def main() -> int:
    """Run one measurement or report a bounded harness failure."""

    try:
        arguments = parser().parse_args()
        required = tuple(
            name for name in vars(arguments)
            if name not in {"cgroup_parent", "source_commit", "mechanism"}
        )
        if any(getattr(arguments, name) is None for name in required):
            raise MeasurementRunError("measurement path argument is absent")
        paths = [getattr(arguments, name) for name in required]
        if arguments.cgroup_parent is not None:
            paths.append(arguments.cgroup_parent)
        if any(not path.is_absolute() for path in paths):
            raise MeasurementRunError("measurement paths must be absolute")
        if arguments.mechanism == "cgroup-endpoint" and arguments.cgroup_parent is None:
            raise MeasurementRunError("endpoint measurement requires a cgroup parent")
        run_bounded(arguments)
        return 0
    except (
        MeasurementDomainError,
        MeasurementObservationError,
        MeasurementRunError,
        OSError,
        RecordError,
        RoutingCellError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"network measurement failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
