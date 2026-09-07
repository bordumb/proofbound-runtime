use std::{fs, path::Path};

use proofbound_runtime_core::parse_execution_plan;

#[test]
fn accepts_registered_positive_plans() {
    for path in plan_paths("positive") {
        let source = fs::read_to_string(&path).expect("plan fixture is readable");
        let plan = parse_execution_plan(&source)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(plan.id().as_str(), "conformance.minimal");
        assert_eq!(plan.command().executable().as_str(), "/bin/tool");
        assert!(plan.command().arguments().is_empty());
        assert_eq!(plan.command().working_directory().as_str(), ".");
        assert_eq!(plan.authority().paths().len(), 2);
    }
}

#[test]
fn rejects_registered_negative_plans_with_exact_codes() {
    for path in plan_paths("negative") {
        let source = fs::read_to_string(&path).expect("plan fixture is readable");
        let expected_path = path.with_extension("error");
        let expected = fs::read_to_string(&expected_path)
            .unwrap_or_else(|error| panic!("{}: {error}", expected_path.display()));
        let error = match parse_execution_plan(&source) {
            Ok(_) => panic!("{}: negative plan was accepted", path.display()),
            Err(error) => error,
        };
        assert_eq!(error.code(), expected.trim(), "{}", path.display());
    }
}

fn plan_paths(class: &str) -> Vec<std::path::PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/conformance/plan")
        .join(class);
    let mut paths = fs::read_dir(root)
        .expect("plan conformance directory exists")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}
