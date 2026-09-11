#![forbid(unsafe_code)]

//! Produces operational Runtime performance metadata outside the assurance
//! evidence boundary.

#[cfg(test)]
mod tests {
    use super::{BenchmarkError, Summary, summarize};

    #[test]
    fn summary_uses_frozen_integer_statistics() {
        assert_eq!(
            summarize(vec![4, 1, 3, 2]),
            Ok(Summary {
                samples_ns: vec![1, 2, 3, 4],
                count: 4,
                minimum_ns: 1,
                median_ns: 2,
                p95_ns: 4,
                maximum_ns: 4,
            })
        );
    }

    #[test]
    fn odd_median_and_nearest_rank_p95_are_exact() {
        let samples = (1..=100).rev().collect();
        let summary = summarize(samples).expect("nonempty samples summarize");
        assert_eq!(summary.median_ns, 50);
        assert_eq!(summary.p95_ns, 95);
        assert_eq!(summary.samples_ns, (1..=100).collect::<Vec<_>>());
    }

    #[test]
    fn midpoint_does_not_overflow() {
        let summary = summarize(vec![u64::MAX, u64::MAX - 2])
            .expect("large samples summarize");
        assert_eq!(summary.median_ns, u64::MAX - 1);
    }

    #[test]
    fn empty_series_fails_closed() {
        assert_eq!(summarize(Vec::new()), Err(BenchmarkError::EmptySeries));
    }
}
