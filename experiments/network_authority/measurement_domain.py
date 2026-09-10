#!/usr/bin/env python3
"""Closed measurement domain for experiment 0001I."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:
    import tomli as toml  # type: ignore[no-redef]


MAX_DOMAIN_BYTES = 65536
SCHEMA = "proofbound-runtime-network-measurement-domain/1"
ARCHITECTURES = ("x86_64", "aarch64")
MECHANISMS = (
    "landlock-port",
    "cgroup-endpoint",
    "explicit-broker",
    "preconnected-channel",
)
INVENTORY_CATEGORIES = (
    "trusted-binaries",
    "source-configuration",
    "certificates",
    "bpf-programs",
    "bpf-maps",
    "landlock-rules",
    "control-channels",
)
SYSTEM_OBSERVATIONS = (
    "effective-capabilities",
    "namespace-operations",
    "cgroup-v2-controllers",
    "landlock-abi",
    "bpf-features",
    "tls-implementation",
    "monotonic-clock",
)
RESIDUAL_AUTHORITIES = (
    "direct-tcp-to-any-address-on-allowed-port",
    "direct-tcp-to-selected-endpoint",
    "child-controlled-resolution",
    "child-controlled-tls",
    "arbitrary-application-bytes",
    "registered-operation-via-mediator",
    "arbitrary-application-bytes-on-authenticated-session",
)
LIFECYCLE_FAILURE_CODES = (
    "create-failed",
    "failure-injection-failed",
    "request-released",
    "cleanup-failed",
    "resource-survived",
    "observation-invalid",
)
ROOT_FIELDS = {
    "schema",
    "architectures",
    "mechanisms",
    "duration_unit",
    "sample_order",
    "setup_sample_count",
    "request_sample_count",
    "median_algorithm",
    "p95_algorithm",
    "lifecycle_iteration_count",
    "lifecycle_bit_order",
    "maximum_seconds",
    "inventory_categories",
    "system_observations",
    "residual_authorities",
    "lifecycle_failure_codes",
    "request",
    "profiles",
}
REQUEST = {
    "service_name": "allowed.test",
    "address": "127.0.0.1",
    "port": 443,
    "transport": "tcp",
    "application_protocol": "https",
    "method": "GET",
    "path": "/v1/echo",
    "response_body": "0123456789abcdef0123456789abcdef",
}
PROFILE_FIELDS = {
    "id",
    "setup_subject",
    "request_subject",
    "mediator_metrics",
    "nonzero_inventory_categories",
    "required_harness_features",
    "required_mechanism_features",
    "expected_residual_authority",
}
PROFILE_RULES = {
    "landlock-port": {
        "mediator_metrics": False,
        "nonzero_inventory_categories": (
            "trusted-binaries", "source-configuration", "certificates",
            "landlock-rules",
        ),
        "required_harness_features": (
            "root", "network-namespace", "mount-namespace",
        ),
        "required_mechanism_features": (
            "landlock-abi-4", "landlock-access-net-connect-tcp",
        ),
        "expected_residual_authority": (
            "direct-tcp-to-any-address-on-allowed-port",
            "child-controlled-resolution",
            "child-controlled-tls",
            "arbitrary-application-bytes",
        ),
    },
    "cgroup-endpoint": {
        "mediator_metrics": False,
        "nonzero_inventory_categories": (
            "trusted-binaries", "source-configuration", "certificates",
            "bpf-programs",
        ),
        "required_harness_features": (
            "root", "network-namespace", "mount-namespace", "cgroup-v2",
        ),
        "required_mechanism_features": (
            "bpf-cgroup-inet4-connect", "bpf-cgroup-inet6-connect",
        ),
        "expected_residual_authority": (
            "direct-tcp-to-selected-endpoint",
            "child-controlled-tls",
            "arbitrary-application-bytes",
        ),
    },
    "explicit-broker": {
        "mediator_metrics": True,
        "nonzero_inventory_categories": (
            "trusted-binaries", "source-configuration", "certificates",
            "control-channels",
        ),
        "required_harness_features": (
            "root", "network-namespace", "mount-namespace",
        ),
        "required_mechanism_features": (
            "seccomp-deny-child-network", "broker-owned-python-tls",
        ),
        "expected_residual_authority": ("registered-operation-via-mediator",),
    },
    "preconnected-channel": {
        "mediator_metrics": True,
        "nonzero_inventory_categories": (
            "trusted-binaries", "source-configuration", "certificates",
            "control-channels",
        ),
        "required_harness_features": (
            "root", "network-namespace", "mount-namespace",
        ),
        "required_mechanism_features": (
            "seccomp-deny-child-network", "connector-owned-python-tls",
        ),
        "expected_residual_authority": (
            "arbitrary-application-bytes-on-authenticated-session",
        ),
    },
}


class MeasurementDomainError(Exception):
    """The registered measurement domain is incomplete or inconsistent."""


@dataclass(frozen=True)
class MeasurementProfile:
    """One exact mechanism measurement profile."""

    identifier: str
    setup_subject: str
    request_subject: str
    mediator_metrics: bool
    nonzero_inventory_categories: tuple[str, ...]
    required_harness_features: tuple[str, ...]
    required_mechanism_features: tuple[str, ...]
    expected_residual_authority: tuple[str, ...]


@dataclass(frozen=True)
class MeasurementDomain:
    """The validated experiment 0001I domain."""

    source_sha256: str
    profiles: tuple[MeasurementProfile, ...]

    def profile(self, mechanism: str) -> MeasurementProfile:
        """Return one registered profile."""

        matches = [item for item in self.profiles if item.identifier == mechanism]
        if len(matches) != 1:
            raise MeasurementDomainError("measurement profile is not unique")
        return matches[0]


def _exact_list(value: object, expected: tuple[str, ...], field: str) -> None:
    if not isinstance(value, list) or tuple(value) != expected:
        raise MeasurementDomainError(f"measurement {field} is not exact")


def load_measurement_domain(path: Path) -> MeasurementDomain:
    """Read and validate the complete measurement protocol."""

    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise MeasurementDomainError("measurement domain is not one regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_DOMAIN_BYTES:
        raise MeasurementDomainError("measurement domain size is invalid")
    try:
        decoded = toml.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise MeasurementDomainError("measurement domain does not decode") from error
    if not isinstance(decoded, dict) or set(decoded) != ROOT_FIELDS:
        raise MeasurementDomainError("measurement domain root is not closed")
    if decoded["schema"] != SCHEMA:
        raise MeasurementDomainError("measurement domain schema is unsupported")
    _exact_list(decoded["architectures"], ARCHITECTURES, "architectures")
    _exact_list(decoded["mechanisms"], MECHANISMS, "mechanisms")
    _exact_list(
        decoded["inventory_categories"], INVENTORY_CATEGORIES, "inventory categories"
    )
    _exact_list(
        decoded["system_observations"], SYSTEM_OBSERVATIONS, "system observations"
    )
    _exact_list(
        decoded["residual_authorities"], RESIDUAL_AUTHORITIES,
        "residual authority vocabulary",
    )
    _exact_list(
        decoded["lifecycle_failure_codes"], LIFECYCLE_FAILURE_CODES,
        "lifecycle failure vocabulary",
    )
    scalars = {
        "duration_unit": "nanoseconds",
        "sample_order": "ascending",
        "setup_sample_count": 100,
        "request_sample_count": 100,
        "median_algorithm": "midpoint-floor",
        "p95_algorithm": "nearest-rank",
        "lifecycle_iteration_count": 1000,
        "lifecycle_bit_order": "least-significant-bit-first",
        "maximum_seconds": 600,
    }
    for field, expected in scalars.items():
        if type(decoded[field]) is not type(expected) or decoded[field] != expected:
            raise MeasurementDomainError(f"measurement {field} changed")
    if decoded["request"] != REQUEST:
        raise MeasurementDomainError("measurement request changed")
    raw_profiles = decoded["profiles"]
    if not isinstance(raw_profiles, list) or len(raw_profiles) != len(MECHANISMS):
        raise MeasurementDomainError("measurement profile inventory is invalid")
    profiles = []
    for index, value in enumerate(raw_profiles):
        if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
            raise MeasurementDomainError("measurement profile schema is not closed")
        identifier = value["id"]
        if identifier != MECHANISMS[index]:
            raise MeasurementDomainError("measurement profile order is not exact")
        if not all(
            isinstance(value[field], str) and value[field]
            for field in ("setup_subject", "request_subject")
        ):
            raise MeasurementDomainError("measurement subject is invalid")
        rules = PROFILE_RULES[identifier]
        if type(value["mediator_metrics"]) is not bool:
            raise MeasurementDomainError("mediator metric selection is invalid")
        for field, expected in rules.items():
            actual = value[field]
            if isinstance(expected, tuple):
                if not isinstance(actual, list) or tuple(actual) != expected:
                    raise MeasurementDomainError(
                        f"measurement profile {identifier} {field} changed"
                    )
            elif actual != expected:
                raise MeasurementDomainError(
                    f"measurement profile {identifier} {field} changed"
                )
        profiles.append(
            MeasurementProfile(
                identifier=identifier,
                setup_subject=value["setup_subject"],
                request_subject=value["request_subject"],
                mediator_metrics=value["mediator_metrics"],
                nonzero_inventory_categories=tuple(
                    value["nonzero_inventory_categories"]
                ),
                required_harness_features=tuple(value["required_harness_features"]),
                required_mechanism_features=tuple(
                    value["required_mechanism_features"]
                ),
                expected_residual_authority=tuple(
                    value["expected_residual_authority"]
                ),
            )
        )
    return MeasurementDomain(hashlib.sha256(raw).hexdigest(), tuple(profiles))
