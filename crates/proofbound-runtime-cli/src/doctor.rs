use std::io;

use proofbound_runtime_linux::{Capability, CapabilityReport, ProbeError};
use serde_json::{Value, json};

const REPORT_SCHEMA: &str = "proofbound-runtime-doctor/2";
const EXPLANATION_SCHEMA: &str = "proofbound-runtime-doctor-explanation/2";

const PROBE_COMMAND: &str = "__proofbound_egress_doctor_probe_v1";

#[cfg(target_os = "linux")]
pub(crate) fn run_probe_child() -> u8 {
    use proofbound_runtime_linux::egress_namespace::{
        EgressNamespaceError, create_egress_namespace,
    };
    match create_egress_namespace() {
        Ok(_) => 0,
        Err(
            EgressNamespaceError::Loopback
            | EgressNamespaceError::InterfaceInventory
            | EgressNamespaceError::RouteInventory
            | EgressNamespaceError::Listener,
        ) => 11,
        Err(_) => 10,
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) const fn run_probe_child() -> u8 {
    10
}

pub(crate) fn write_report(
    report: &CapabilityReport,
    output: &mut impl io::Write,
) -> io::Result<bool> {
    write(report, false, output)
}

pub(crate) fn write_explanation(
    report: &CapabilityReport,
    output: &mut impl io::Write,
) -> io::Result<bool> {
    write(report, true, output)
}

fn write(
    report: &CapabilityReport,
    explain: bool,
    output: &mut impl io::Write,
) -> io::Result<bool> {
    let supported = report.clone().require_supported().is_ok();
    let (user_namespace, network_namespace, landlock_egress) = egress_capabilities(report, explain);
    let value = json!({
        "schema": if explain { EXPLANATION_SCHEMA } else { REPORT_SCHEMA },
        "supported": supported,
        "capabilities": {
            "operating_system": capability(&report.operating_system, explain, |()| {
                json!({"name": "linux"})
            }),
            "architecture": capability(&report.architecture, explain, |architecture| {
                json!({"name": architecture.as_str()})
            }),
            "kernel_release": capability(&report.kernel_release, explain, |release| {
                json!({"release": release})
            }),
            "landlock": capability(&report.landlock_abi, explain, |abi| {
                json!({"abi": abi.get()})
            }),
            "user_namespace": user_namespace,
            "network_namespace": network_namespace,
            "landlock_egress": landlock_egress,
            "no_new_privileges": capability(&report.no_new_privileges, explain, |()| {
                json!({"enabled": true})
            }),
            "seccomp": capability(&report.seccomp, explain, |seccomp| {
                json!({"available_actions": seccomp.available_actions()})
            }),
            "cgroup_v2": capability(&report.cgroup_v2, explain, |cgroup| {
                json!({
                    "directory": cgroup.directory().to_string_lossy(),
                    "mount_id": cgroup.mount_id(),
                    "directory_inode": cgroup.directory_inode(),
                    "controllers": cgroup.controllers(),
                    "proxy_sibling_supported": true,
                })
            }),
        },
    });
    serde_json::to_writer(&mut *output, &value).map_err(io::Error::other)?;
    writeln!(output)?;
    Ok(supported)
}

fn egress_capabilities(report: &CapabilityReport, explain: bool) -> (Value, Value, Value) {
    let landlock = match &report.landlock_abi {
        Capability::Available(abi) if (9..=11).contains(&abi.get()) => {
            json!({"status": "available", "abi": abi.get()})
        }
        _ => egress_unavailable(
            "host.landlock.abi-below-egress",
            explain,
            "Landlock ABI 9 through 11",
            "use a host with a reviewed Landlock egress ABI",
        ),
    };
    #[cfg(not(target_os = "linux"))]
    return (
        egress_unavailable(
            "host.userns.probe-failed",
            explain,
            "an unprivileged user namespace with identity maps",
            "use supported native Linux",
        ),
        egress_unavailable(
            "host.netns.probe-failed",
            explain,
            "a fresh loopback-only network namespace",
            "use supported native Linux",
        ),
        landlock,
    );
    #[cfg(target_os = "linux")]
    {
        if !matches!(report.operating_system, Capability::Available(())) {
            return (
                egress_unavailable(
                    "host.userns.probe-failed",
                    explain,
                    "an unprivileged user namespace with identity maps",
                    "use supported native Linux",
                ),
                egress_unavailable(
                    "host.netns.probe-failed",
                    explain,
                    "a fresh loopback-only network namespace",
                    "use supported native Linux",
                ),
                landlock,
            );
        }
        let user_max = read_sysctl("/proc/sys/user/max_user_namespaces");
        let user_clone = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone");
        let net_max = read_sysctl("/proc/sys/user/max_net_namespaces");
        let disabled_user = user_max == Some(0) || user_clone == Some(0);
        let disabled_net = net_max == Some(0);
        if disabled_user {
            return (
                egress_unavailable(
                    "host.userns.sysctl-disabled",
                    explain,
                    "nonzero user.max_user_namespaces and enabled unprivileged user namespaces",
                    "ask the host administrator to permit unprivileged user namespaces for the installed launcher",
                ),
                egress_unavailable(
                    "host.netns.probe-failed",
                    explain,
                    "a fresh loopback-only network namespace",
                    "enable user namespaces first",
                ),
                landlock,
            );
        }
        if disabled_net {
            return (
                egress_unavailable(
                    "host.userns.probe-failed",
                    explain,
                    "an unprivileged user namespace with identity maps",
                    "enable network namespaces before probing",
                ),
                egress_unavailable(
                    "host.netns.sysctl-disabled",
                    explain,
                    "nonzero user.max_net_namespaces",
                    "ask the host administrator to permit network namespaces",
                ),
                landlock,
            );
        }
        let status = std::env::current_exe()
            .ok()
            .and_then(|program| {
                std::process::Command::new(program)
                    .arg(PROBE_COMMAND)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .ok()
            })
            .and_then(|status| status.code());
        let user = match status {
            Some(0 | 11) => json!({"status": "available", "identity_maps": true}),
            _ if read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                == Some(1) =>
            {
                egress_unavailable(
                    "host.userns.apparmor-restricted",
                    explain,
                    "an unprivileged user namespace with identity maps",
                    "ask the host administrator to grant user namespaces to the exact installed launcher",
                )
            }
            _ => egress_unavailable(
                "host.userns.probe-failed",
                explain,
                "an unprivileged user namespace with identity maps",
                "inspect the host user namespace policy and retry",
            ),
        };
        let network = match status {
            Some(0) => json!({"status": "available", "loopback_listener": "127.0.0.1:3128"}),
            Some(11) => egress_unavailable(
                "host.netns.loopback-failed",
                explain,
                "a loopback-only network namespace with a bound proxy listener",
                "inspect loopback setup and listener restrictions in the host kernel",
            ),
            _ => egress_unavailable(
                "host.netns.probe-failed",
                explain,
                "a fresh loopback-only network namespace",
                "inspect host network namespace policy and retry",
            ),
        };
        (user, network, landlock)
    }
}

#[cfg(target_os = "linux")]
fn read_sysctl(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn egress_unavailable(code: &str, explain: bool, requirement: &str, remediation: &str) -> Value {
    if explain {
        json!({"status": "unavailable", "code": code,
            "requirement": requirement, "remediation": remediation})
    } else {
        json!({"status": "unavailable", "code": code})
    }
}

fn capability<T>(
    value: &Capability<T>,
    explain: bool,
    available: impl FnOnce(&T) -> Value,
) -> Value {
    match value {
        Capability::Available(value) => {
            let Value::Object(mut fields) = available(value) else {
                unreachable!("capability details are JSON objects");
            };
            fields.insert("status".to_owned(), Value::String("available".to_owned()));
            Value::Object(fields)
        }
        Capability::Unavailable(error) => {
            let mut fields = serde_json::Map::from_iter([
                ("status".to_owned(), Value::String("unavailable".to_owned())),
                ("code".to_owned(), Value::String(error.code().to_owned())),
            ]);
            if explain {
                let explanation = explanation(*error);
                fields.insert(
                    "requirement".to_owned(),
                    Value::String(explanation.requirement.to_owned()),
                );
                fields.insert(
                    "remediation".to_owned(),
                    Value::String(explanation.remediation.to_owned()),
                );
            }
            Value::Object(fields)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Explanation {
    requirement: &'static str,
    remediation: &'static str,
}

const fn explanation(error: ProbeError) -> Explanation {
    match error {
        ProbeError::UnsupportedOperatingSystem => Explanation {
            requirement: "native Linux operating system",
            remediation: "use native Linux x86_64 or aarch64; other hosts support only plan validation and receipt inspection",
        },
        ProbeError::UnsupportedArchitecture => Explanation {
            requirement: "Linux x86_64 or aarch64 architecture",
            remediation: "use a supported native Linux x86_64 or aarch64 host",
        },
        ProbeError::KernelReleaseUnavailable => Explanation {
            requirement: "readable non-empty Linux kernel release",
            remediation: "mount procfs at /proc and make /proc/sys/kernel/osrelease readable",
        },
        ProbeError::LandlockUnavailable => Explanation {
            requirement: "kernel Landlock ABI query",
            remediation: "use a Linux kernel with Landlock enabled; do not continue without filesystem enforcement",
        },
        ProbeError::LandlockAbiUnsupported => Explanation {
            requirement: "reviewed Landlock ABI from 3 through 11",
            remediation: "use a host reporting Landlock ABI 3 through 11; a different ABI requires review before use",
        },
        ProbeError::NoNewPrivilegesUnavailable => Explanation {
            requirement: "kernel support for querying and installing no_new_privs",
            remediation: "use a Linux kernel with prctl no_new_privs support; do not continue without it",
        },
        ProbeError::SeccompUnavailable => Explanation {
            requirement: "kernel seccomp filter interface and action inventory",
            remediation: "use a Linux kernel with seccomp filter support and a readable actions_avail interface",
        },
        ProbeError::SeccompActionMissing => Explanation {
            requirement: "seccomp actions allow, errno, and kill_process",
            remediation: "use a Linux kernel that exposes every required seccomp action",
        },
        ProbeError::CgroupV2Unavailable => Explanation {
            requirement: "mounted unified cgroup v2 hierarchy and resolvable configured root",
            remediation: "use cgroup v2 and pass an existing path below its unified hierarchy",
        },
        ProbeError::CgroupV2DelegationUnavailable => Explanation {
            requirement: "empty writable delegated cgroup v2 root above the supervisor with pids enabled",
            remediation: "enter the maintained systemd delegation profile and pass its empty delegated root",
        },
        ProbeError::CgroupV2ControllerMissing => Explanation {
            requirement: "pids controller delegated to the configured cgroup root",
            remediation: "start the service with Delegate=pids memory and verify both controllers are available below the delegated root",
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use proofbound_runtime_linux::probe_capabilities;

    use super::*;

    #[test]
    fn report_is_closed_json_and_support_matches_the_probe() {
        let report = probe_capabilities(Path::new("/definitely-not-a-cgroup-delegation"));
        let expected_supported = report.clone().require_supported().is_ok();
        let mut output = Vec::new();
        let supported = write_report(&report, &mut output).expect("doctor report writes");
        let value: Value = serde_json::from_slice(&output).expect("doctor report is JSON");

        assert_eq!(supported, expected_supported);
        assert_eq!(value["schema"], REPORT_SCHEMA);
        assert_eq!(value["supported"], expected_supported);
        let capabilities = value["capabilities"]
            .as_object()
            .expect("capabilities object");
        assert_eq!(capabilities.len(), 10);
        assert!(capabilities.values().all(|entry| {
            matches!(entry["status"].as_str(), Some("available" | "unavailable"))
        }));
        assert!(capabilities.values().all(|entry| {
            entry["status"] != "unavailable"
                || entry.as_object().is_some_and(|fields| fields.len() == 2)
        }));
    }

    #[test]
    fn explanation_adds_bounded_guidance_without_changing_support() {
        let report = probe_capabilities(Path::new("/definitely-not-a-cgroup-delegation"));
        let expected_supported = report.clone().require_supported().is_ok();
        let mut output = Vec::new();
        let supported = write_explanation(&report, &mut output).expect("doctor explanation writes");
        let value: Value = serde_json::from_slice(&output).expect("doctor explanation is JSON");

        assert_eq!(supported, expected_supported);
        assert_eq!(value["schema"], EXPLANATION_SCHEMA);
        assert_eq!(value["supported"], expected_supported);
        for entry in value["capabilities"]
            .as_object()
            .expect("capabilities object")
            .values()
            .filter(|entry| entry["status"] == "unavailable")
        {
            let fields = entry.as_object().expect("unavailable capability object");
            assert_eq!(fields.len(), 4);
            assert!(
                fields["requirement"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty())
            );
            assert!(
                fields["remediation"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty())
            );
        }
    }

    #[test]
    fn every_probe_error_has_distinct_code_and_nonempty_explanation() {
        let errors = [
            ProbeError::UnsupportedOperatingSystem,
            ProbeError::UnsupportedArchitecture,
            ProbeError::KernelReleaseUnavailable,
            ProbeError::LandlockUnavailable,
            ProbeError::LandlockAbiUnsupported,
            ProbeError::NoNewPrivilegesUnavailable,
            ProbeError::SeccompUnavailable,
            ProbeError::SeccompActionMissing,
            ProbeError::CgroupV2Unavailable,
            ProbeError::CgroupV2DelegationUnavailable,
            ProbeError::CgroupV2ControllerMissing,
        ];
        let codes: std::collections::BTreeSet<_> =
            errors.iter().map(|error| error.code()).collect();

        assert_eq!(codes.len(), errors.len());
        for error in errors {
            let value = explanation(error);
            assert!(!value.requirement.is_empty());
            assert!(!value.remediation.is_empty());
        }
    }

    #[test]
    fn output_failures_are_reported() {
        struct RejectWrites;

        impl io::Write for RejectWrites {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::WriteZero))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let report = probe_capabilities(Path::new("/unsupported"));
        let error = write_report(&report, &mut RejectWrites)
            .expect_err("a closed writer rejects the report");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
}
