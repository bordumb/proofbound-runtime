#![forbid(unsafe_code)]

fn main() {}

#[cfg(test)]
mod tests {
    use super::{Arguments, CliError, parse_arguments};

    #[test]
    fn arguments_accept_one_exact_pure_source() {
        let revision = "a".repeat(40);
        assert_eq!(
            parse_arguments([
                "pbr-bench".to_owned(),
                "pure".to_owned(),
                "--source-commit".to_owned(),
                revision.clone(),
            ]),
            Ok(Arguments {
                source_commit: revision,
            })
        );
    }

    #[test]
    fn arguments_reject_missing_extra_and_noncanonical_sources() {
        for arguments in [
            vec!["pbr-bench"],
            vec!["pbr-bench", "native", "--source-commit", "a"],
            vec!["pbr-bench", "pure", "--source-commit", "a"],
            vec![
                "pbr-bench",
                "pure",
                "--source-commit",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "extra",
            ],
        ] {
            assert_eq!(
                parse_arguments(arguments.into_iter().map(str::to_owned)),
                Err(CliError::Usage)
            );
        }
    }
}
