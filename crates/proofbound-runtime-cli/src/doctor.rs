use std::io;

use proofbound_runtime_linux::{Capability, CapabilityReport};
use serde_json::{Value, json};

const REPORT_SCHEMA: &str = "proofbound-runtime-doctor/1";

pub(crate) fn write_report(
    report: &CapabilityReport,
    output: &mut impl io::Write,
) -> io::Result<bool> {
    let supported = report.clone().require_supported().is_ok();
    let value = json!({
        "schema": REPORT_SCHEMA,
        "supported": supported,
        "capabilities": {
            "operating_system": capability(&report.operating_system, |()| {
                json!({"name": "linux"})
            }),
            "architecture": capability(&report.architecture, |architecture| {
                json!({"name": architecture.as_str()})
            }),
            "kernel_release": capability(&report.kernel_release, |release| {
                json!({"release": release})
            }),
            "landlock": capability(&report.landlock_abi, |abi| {
                json!({"abi": abi.get()})
            }),
            "no_new_privileges": capability(&report.no_new_privileges, |()| {
                json!({"enabled": true})
            }),
            "seccomp": capability(&report.seccomp, |seccomp| {
                json!({"available_actions": seccomp.available_actions()})
            }),
            "cgroup_v2": capability(&report.cgroup_v2, |cgroup| {
                json!({
                    "directory": cgroup.directory().to_string_lossy(),
                    "mount_id": cgroup.mount_id(),
                    "directory_inode": cgroup.directory_inode(),
                    "controllers": cgroup.controllers(),
                })
            }),
        },
    });
    serde_json::to_writer(&mut *output, &value).map_err(io::Error::other)?;
    writeln!(output)?;
    Ok(supported)
}

fn capability<T>(value: &Capability<T>, available: impl FnOnce(&T) -> Value) -> Value {
    match value {
        Capability::Available(value) => {
            let Value::Object(mut fields) = available(value) else {
                unreachable!("capability details are JSON objects");
            };
            fields.insert("status".to_owned(), Value::String("available".to_owned()));
            Value::Object(fields)
        }
        Capability::Unavailable(error) => json!({
            "status": "unavailable",
            "code": error.code(),
        }),
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
        assert_eq!(capabilities.len(), 7);
        assert!(capabilities.values().all(|entry| {
            matches!(entry["status"].as_str(), Some("available" | "unavailable"))
        }));
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
