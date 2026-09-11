#![forbid(unsafe_code)]

//! Produces operational Runtime performance metadata outside the assurance
//! evidence boundary.

use core::fmt;

use serde::Serialize;

/// One closed benchmark-harness failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkError {
    /// A measured series contained no samples.
    EmptySeries,
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("benchmark.series.empty")
    }
}

impl std::error::Error for BenchmarkError {}

/// Exact sorted samples and their frozen integer summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Summary {
    /// Raw elapsed nanoseconds in ascending order.
    pub samples_ns: Vec<u64>,
    /// Number of raw samples.
    pub count: usize,
    /// Smallest observed duration.
    pub minimum_ns: u64,
    /// Integer midpoint median.
    pub median_ns: u64,
    /// Nearest-rank 95th percentile.
    pub p95_ns: u64,
    /// Largest observed duration.
    pub maximum_ns: u64,
}

/// Sorts and summarizes one nonempty elapsed-time series.
pub fn summarize(mut samples_ns: Vec<u64>) -> Result<Summary, BenchmarkError> {
    if samples_ns.is_empty() {
        return Err(BenchmarkError::EmptySeries);
    }
    samples_ns.sort_unstable();
    let count = samples_ns.len();
    let median_ns = if count.is_multiple_of(2) {
        let lower = samples_ns[count / 2 - 1];
        let upper = samples_ns[count / 2];
        lower + (upper - lower) / 2
    } else {
        samples_ns[count / 2]
    };
    // ceil(0.95 * count) equals count - floor(count / 20).
    let p95_index = count - count / 20 - 1;

    Ok(Summary {
        minimum_ns: samples_ns[0],
        median_ns,
        p95_ns: samples_ns[p95_index],
        maximum_ns: samples_ns[count - 1],
        samples_ns,
        count,
    })
}

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
        let summary = summarize(vec![u64::MAX, u64::MAX - 2]).expect("large samples summarize");
        assert_eq!(summary.median_ns, u64::MAX - 1);
    }

    #[test]
    fn empty_series_fails_closed() {
        assert_eq!(summarize(Vec::new()), Err(BenchmarkError::EmptySeries));
    }
}
