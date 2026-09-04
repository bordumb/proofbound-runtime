use std::{fs, path::Path, process::Command};

use proofbound_runtime_core::{
    AuthorityPath, AuthorityPlan, EnvironmentName, FileAccess, NormalizedAuthority,
    OutputByteLimit, PathAuthority, PathRole, ProcessLimit, ResourceLimits, WallTimeLimit,
    normalize_authority,
};
use serde_json::{Value, json};

const SCHEMA: &str = "proofbound-runtime-authority-vector/1";

#[test]
fn accepts_all_positive_authority_vectors() {
    for (path, vector) in vectors("positive") {
        let plan =
            parse_plan(&vector).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let normalized = normalize_authority(plan.clone());
        assert!(normalized.is_subset_of(&plan), "{}", path.display());
        assert!(normalized.is_canonical(), "{}", path.display());
        assert_eq!(
            encode(&normalized),
            vector["expected"],
            "{}",
            path.display()
        );
    }
}

#[test]
fn rejects_all_negative_authority_vectors() {
    for (path, vector) in vectors("negative") {
        let expected = text(&vector, "expected_error").expect("fixture has expected_error");
        assert_eq!(
            parse_plan(&vector).expect_err("negative fixture must fail"),
            expected,
            "{}",
            path.display()
        );
    }
}

#[test]
fn independent_reference_accepts_registered_vectors() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new("python3")
        .arg(root.join("tools/conformance/authority_reference.py"))
        .current_dir(root)
        .status()
        .expect("python3 must run the independent reference interpreter");
    assert!(status.success());
}

fn vectors(class: &str) -> Vec<(std::path::PathBuf, Value)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/conformance")
        .join(class);
    let mut paths = fs::read_dir(root)
        .expect("conformance directory exists")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).expect("readable conformance vector");
            let value = serde_json::from_slice(&bytes).expect("valid JSON conformance vector");
            (path, value)
        })
        .collect()
}

fn parse_plan(vector: &Value) -> Result<AuthorityPlan, &'static str> {
    if text(vector, "schema")? != SCHEMA {
        return Err("authority.vector.schema");
    }
    let input = object(vector, "input")?;
    if text(input, "network")? != "deny" {
        return Err("authority.network.unsupported");
    }

    let paths = array(input, "paths")?
        .iter()
        .map(|item| {
            let path =
                AuthorityPath::new(text_value(item, "path")?).map_err(|error| error.code())?;
            let access = match text_value(item, "access")? {
                "read" => FileAccess::Read,
                "write" => FileAccess::Write,
                "execute" => FileAccess::Execute,
                _ => return Err("authority.access.unsupported"),
            };
            let role = match text_value(item, "role")? {
                "project-input" => PathRole::ProjectInput,
                "output-root" => PathRole::OutputRoot,
                "runtime-executable" => PathRole::RuntimeExecutable,
                "runtime-loader-executable" => PathRole::RuntimeLoaderExecutable,
                "runtime-library" => PathRole::RuntimeLibrary,
                _ => return Err("authority.path_role.unsupported"),
            };
            Ok(PathAuthority::new(path, access, role))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let environment = array(input, "environment")?
        .iter()
        .map(|item| {
            let name = item.as_str().ok_or("authority.vector.type")?;
            EnvironmentName::new(name).map_err(|error| error.code())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let limits = object(input, "limits")?;
    let processes = u32::try_from(integer(limits, "processes")?)
        .map_err(|_| "authority.limit.processes.range")?;
    let limits = ResourceLimits::new(
        ProcessLimit::new(processes).map_err(|error| error.code())?,
        WallTimeLimit::from_milliseconds(integer(limits, "wall_time_ms")?)
            .map_err(|error| error.code())?,
        OutputByteLimit::new(integer(limits, "stdout_bytes")?),
        OutputByteLimit::new(integer(limits, "stderr_bytes")?),
    );
    Ok(AuthorityPlan::new(paths, environment, limits))
}

fn encode(authority: &NormalizedAuthority) -> Value {
    let paths = authority
        .paths()
        .iter()
        .map(|item| {
            json!({
                "path": item.path().as_str(),
                "access": match item.access() {
                    FileAccess::Read => "read",
                    FileAccess::Write => "write",
                    FileAccess::Execute => "execute",
                },
                "role": match item.role() {
                    PathRole::ProjectInput => "project-input",
                    PathRole::OutputRoot => "output-root",
                    PathRole::RuntimeExecutable => "runtime-executable",
                    PathRole::RuntimeLoaderExecutable => "runtime-loader-executable",
                    PathRole::RuntimeLibrary => "runtime-library",
                }
            })
        })
        .collect::<Vec<_>>();
    let limits = authority.limits();
    json!({
        "paths": paths,
        "environment": authority.environment().iter().map(EnvironmentName::as_str).collect::<Vec<_>>(),
        "limits": {
            "processes": limits.processes().get(),
            "wall_time_ms": limits.wall_time().milliseconds(),
            "stdout_bytes": limits.stdout().get(),
            "stderr_bytes": limits.stderr().get()
        },
        "network": "deny"
    })
}

fn object<'a>(value: &'a Value, key: &str) -> Result<&'a Value, &'static str> {
    value
        .get(key)
        .filter(|item| item.is_object())
        .ok_or("authority.vector.type")
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, &'static str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or("authority.vector.type")
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    text_value(value, key)
}

fn text_value<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("authority.vector.type")
}

fn integer(value: &Value, key: &str) -> Result<u64, &'static str> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or("authority.vector.type")
}
