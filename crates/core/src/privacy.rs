//! Visitor identification without identifying visitors.
//!
//! Cairn needs to answer "how many distinct people visited today" without
//! storing anything that points back at a person. The mechanism is a keyed hash
//! of the things that happen to be stable for one browser on one day, using a
//! key that is thrown away and regenerated every day.
//!
//! The daily rotation is the part that matters. A fixed salt would produce a
//! stable pseudonym that follows someone across months, which is the thing
//! cookie banners exist to warn about. Rotating the key daily means yesterday's
//! IDs cannot be linked to today's even by us, even with the raw logs, because
//! the key that would connect them no longer exists.

use blake3::Hasher;
use time::Date;

/// Domain-separation tags. Hashing different things with the same key is safe
/// only if the inputs can never be confused for one another, so each use gets
/// its own prefix.
const SALT_DOMAIN: &[u8] = b"cairn/daily-salt/v1";
const VISITOR_DOMAIN: &[u8] = b"cairn/visitor-id/v1";

/// Number of bytes of the digest kept for a visitor ID, before hex encoding.
///
/// Eight bytes is 64 bits, which is far more than enough: the ID only has to be
/// distinct among the visitors to one site on one day. Truncating is not a
/// weakness here, it is deliberate, since a shorter ID leaks strictly less if
/// the table is ever exposed.
const VISITOR_ID_BYTES: usize = 8;

/// The hashing key in force for a single UTC day.
///
/// Intentionally not `Debug`-derived, and not `Serialize`. This value is the
/// one secret that makes visitor IDs irreversible, so the easiest way to leak
/// it is an idle `tracing::info!("{salt:?}")`. The manual `Debug` below makes
/// that impossible rather than merely discouraged.
#[derive(Clone)]
pub struct DailySalt([u8; 32]);

impl DailySalt {
    /// Derive the key for `day` from the long-lived secret.
    ///
    /// `secret` comes from SSM Parameter Store and is stable for the life of
    /// the deployment; `day` is what makes the result rotate. Deriving rather
    /// than storing 365 secrets means there is exactly one value to protect.
    pub fn derive(secret: &[u8], day: Date) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(SALT_DOMAIN);
        hasher.update(&(secret.len() as u64).to_le_bytes());
        hasher.update(secret);
        // Julian day is a plain integer, so this avoids depending on any date
        // formatting and cannot drift with locale or format changes.
        hasher.update(&day.to_julian_day().to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    fn key(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DailySalt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DailySalt(redacted)")
    }
}

/// An opaque per-site, per-day identifier for one visitor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct VisitorId(String);

impl VisitorId {
    /// Hash a visitor's request fingerprint under the day's key.
    ///
    /// `ip` is borrowed for the length of this call and never stored. It exists
    /// nowhere else in the codebase: no struct field, no log line, no DynamoDB
    /// attribute.
    ///
    /// The fields are length-prefixed rather than simply concatenated. Plain
    /// concatenation is ambiguous, and ambiguity here would be a real bug:
    /// `(site: "ab", ip: "c")` and `(site: "a", ip: "bc")` would otherwise
    /// produce the same digest and silently merge two visitors into one.
    pub fn new(salt: &DailySalt, site: &str, ip: &str, user_agent: &str) -> Self {
        let mut hasher = Hasher::new_keyed(salt.key());
        hasher.update(VISITOR_DOMAIN);
        for field in [site.as_bytes(), ip.as_bytes(), user_agent.as_bytes()] {
            hasher.update(&(field.len() as u64).to_le_bytes());
            hasher.update(field);
        }
        Self(hex(&hasher.finalize().as_bytes()[..VISITOR_ID_BYTES]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VisitorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Lowercase hex encoding. Hand-rolled because pulling a dependency for sixteen
/// lines would be more code to audit, not less.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Month;

    const SECRET: &[u8] = b"test-secret-not-the-real-one";

    fn day(y: i32, m: Month, d: u8) -> Date {
        Date::from_calendar_date(y, m, d).expect("valid date")
    }

    fn salt_for(y: i32, m: Month, d: u8) -> DailySalt {
        DailySalt::derive(SECRET, day(y, m, d))
    }

    #[test]
    fn same_visitor_same_day_is_stable() {
        let salt = salt_for(2026, Month::August, 2);
        let a = VisitorId::new(&salt, "site.dev", "203.0.113.7", "Mozilla/5.0");
        let b = VisitorId::new(&salt, "site.dev", "203.0.113.7", "Mozilla/5.0");
        assert_eq!(a, b, "a returning visitor must count once, not twice");
    }

    #[test]
    fn different_ips_differ() {
        let salt = salt_for(2026, Month::August, 2);
        let a = VisitorId::new(&salt, "site.dev", "203.0.113.7", "Mozilla/5.0");
        let b = VisitorId::new(&salt, "site.dev", "203.0.113.8", "Mozilla/5.0");
        assert_ne!(a, b);
    }

    /// The load-bearing privacy property: the same person is unrecognizable
    /// tomorrow. If this ever fails, Cairn is building long-lived pseudonyms
    /// and the "no consent banner needed" claim stops being true.
    #[test]
    fn same_visitor_is_unlinkable_across_days() {
        let today = salt_for(2026, Month::August, 2);
        let tomorrow = salt_for(2026, Month::August, 3);
        let a = VisitorId::new(&today, "site.dev", "203.0.113.7", "Mozilla/5.0");
        let b = VisitorId::new(&tomorrow, "site.dev", "203.0.113.7", "Mozilla/5.0");
        assert_ne!(a, b);
    }

    /// One site must not be able to recognize another site's visitors, so that
    /// hosting several sites on one deployment does not silently build a
    /// cross-site profile.
    #[test]
    fn sites_do_not_share_visitor_ids() {
        let salt = salt_for(2026, Month::August, 2);
        let a = VisitorId::new(&salt, "site-one.dev", "203.0.113.7", "Mozilla/5.0");
        let b = VisitorId::new(&salt, "site-two.dev", "203.0.113.7", "Mozilla/5.0");
        assert_ne!(a, b);
    }

    /// Guards the length-prefixing. Without it these two inputs collide.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let salt = salt_for(2026, Month::August, 2);
        let a = VisitorId::new(&salt, "ab", "c", "ua");
        let b = VisitorId::new(&salt, "a", "bc", "ua");
        assert_ne!(
            a, b,
            "length prefixes must keep fields from bleeding together"
        );
    }

    #[test]
    fn secret_changes_everything() {
        let d = day(2026, Month::August, 2);
        let a = VisitorId::new(&DailySalt::derive(b"one", d), "s", "ip", "ua");
        let b = VisitorId::new(&DailySalt::derive(b"two", d), "s", "ip", "ua");
        assert_ne!(a, b);
    }

    #[test]
    fn visitor_id_is_short_hex() {
        let salt = salt_for(2026, Month::August, 2);
        let id = VisitorId::new(&salt, "site.dev", "203.0.113.7", "Mozilla/5.0");
        assert_eq!(id.as_str().len(), VISITOR_ID_BYTES * 2);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The salt must not be printable, or it will eventually end up in a log.
    #[test]
    fn salt_debug_is_redacted() {
        let salt = salt_for(2026, Month::August, 2);
        assert_eq!(format!("{salt:?}"), "DailySalt(redacted)");
    }

    #[test]
    fn hex_encodes_correctly() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }
}
