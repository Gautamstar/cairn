//! The key schema for aggregate items.
//!
//! This module exists so that the rollup handler that writes aggregates and the
//! query handler that reads them cannot disagree about the format. A sort key
//! built as `"PATH#"` in one crate and parsed as `"PAGE#"` in another is a bug
//! that compiles, deploys, and shows up as an empty dashboard panel, so the
//! construction and the parsing live next to each other and are round-tripped
//! in a test.
//!
//! Aggregates are keyed by site and day:
//!
//! ```text
//! pk = A#gautamstar.github.io#2026-08-02
//! sk = TOTAL              overall views and visitors for the day
//!      HOUR#14            one per hour, for the time series
//!      PATH#/about        one per distinct value, for the ranked panels
//!      REF#google.com
//!      CTRY#CA
//!      BR#Chrome
//!      OS#Windows
//!      DEV#Desktop
//!      EVT#signup
//! ```

use serde::Serialize;

/// Sort key for the whole-day totals item.
pub const TOTAL_KEY: &str = "TOTAL";

const HOUR_PREFIX: &str = "HOUR#";

/// Partition key for every aggregate belonging to one site on one day.
pub fn partition_key(site: &str, day: &str) -> String {
    format!("A#{site}#{day}")
}

/// Sort key for a single hour, zero-padded so string order matches clock order.
pub fn hour_key(hour: u8) -> String {
    format!("{HOUR_PREFIX}{hour:02}")
}

/// Recover the hour from an hour sort key.
pub fn parse_hour(sort_key: &str) -> Option<u8> {
    sort_key.strip_prefix(HOUR_PREFIX)?.parse().ok()
}

/// The ranked breakdowns shown on the dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Path,
    Referrer,
    Country,
    Browser,
    Os,
    Device,
    /// Custom events sent through `cairn('name')`, counted separately from
    /// pageviews so they cannot inflate the view count.
    Event,
}

impl Dimension {
    pub const ALL: [Dimension; 7] = [
        Self::Path,
        Self::Referrer,
        Self::Country,
        Self::Browser,
        Self::Os,
        Self::Device,
        Self::Event,
    ];

    /// Sort key prefix. No prefix here may be a prefix of another one, or
    /// [`Self::parse`] would decode the wrong dimension; the test below pins
    /// that property so a future addition cannot quietly break it.
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Path => "PATH#",
            Self::Referrer => "REF#",
            Self::Country => "CTRY#",
            Self::Browser => "BR#",
            Self::Os => "OS#",
            Self::Device => "DEV#",
            Self::Event => "EVT#",
        }
    }

    /// The name this dimension is given in the JSON the dashboard consumes.
    pub fn json_field(self) -> &'static str {
        match self {
            Self::Path => "pages",
            Self::Referrer => "referrers",
            Self::Country => "countries",
            Self::Browser => "browsers",
            Self::Os => "systems",
            Self::Device => "devices",
            Self::Event => "events",
        }
    }

    pub fn key(self, value: &str) -> String {
        format!("{}{}", self.prefix(), value)
    }

    /// Decode a sort key into its dimension and value, or `None` if it is not a
    /// dimension key at all (`TOTAL` and `HOUR#..` land here).
    pub fn parse(sort_key: &str) -> Option<(Dimension, &str)> {
        Self::ALL.iter().find_map(|dimension| {
            sort_key
                .strip_prefix(dimension.prefix())
                .map(|value| (*dimension, value))
        })
    }
}

/// A views/visitors pair, the payload of every aggregate item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub views: u64,
    pub visitors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_keys_are_site_and_day_scoped() {
        assert_eq!(partition_key("a.dev", "2026-08-02"), "A#a.dev#2026-08-02");
    }

    #[test]
    fn hours_round_trip_and_sort_correctly() {
        assert_eq!(hour_key(7), "HOUR#07");
        assert_eq!(parse_hour("HOUR#07"), Some(7));
        assert_eq!(parse_hour("HOUR#23"), Some(23));
        // Zero padding is what keeps DynamoDB's lexicographic order usable.
        assert!(hour_key(9) < hour_key(10));
    }

    #[test]
    fn non_hour_keys_do_not_parse_as_hours() {
        assert_eq!(parse_hour(TOTAL_KEY), None);
        assert_eq!(parse_hour("PATH#/about"), None);
    }

    #[test]
    fn dimensions_round_trip() {
        for dimension in Dimension::ALL {
            let key = dimension.key("some-value");
            assert_eq!(Dimension::parse(&key), Some((dimension, "some-value")));
        }
    }

    /// Values contain the separator: paths have slashes, referrers have dots,
    /// and an event name could contain anything. Only the first `#` delimits.
    #[test]
    fn values_containing_separators_survive() {
        let key = Dimension::Path.key("/blog/2026/rust#anchor");
        assert_eq!(
            Dimension::parse(&key),
            Some((Dimension::Path, "/blog/2026/rust#anchor"))
        );
    }

    #[test]
    fn total_and_hour_keys_are_not_dimensions() {
        assert_eq!(Dimension::parse(TOTAL_KEY), None);
        assert_eq!(Dimension::parse("HOUR#14"), None);
    }

    /// If one prefix were a prefix of another, `parse` would decode ambiguously
    /// depending on iteration order. This is the guard for adding a new
    /// dimension later.
    #[test]
    fn no_prefix_shadows_another() {
        for outer in Dimension::ALL {
            for inner in Dimension::ALL {
                if outer != inner {
                    assert!(
                        !outer.prefix().starts_with(inner.prefix()),
                        "{} shadows {}",
                        outer.prefix(),
                        inner.prefix()
                    );
                }
            }
        }
    }

    #[test]
    fn json_field_names_are_unique() {
        let mut names: Vec<_> = Dimension::ALL.iter().map(|d| d.json_field()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
