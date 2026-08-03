//! Proving a request arrived through CloudFront.
//!
//! API Gateway endpoints are publicly reachable. Without this check anyone can
//! POST straight to the API and skip CloudFront entirely, which matters because
//! the ingest handler identifies visitors partly from headers CloudFront sets.
//! On a direct call those headers are absent and the handler falls back to
//! `X-Forwarded-For`, which the caller controls completely. The result is that
//! anyone could choose their own visitor ID and inflate the unique-visitor
//! count at will.
//!
//! The fix is the standard one: CloudFront attaches a secret header to every
//! origin request, and requests without it are refused.
//!
//! # What this is and is not worth
//!
//! The secret lives in Terraform state and in the CloudFront distribution
//! config as plaintext. It is not a strong secret and should not be treated as
//! one. It is worth exactly what it protects, which is the integrity of
//! pageview counts on a personal dashboard. No visitor data is exposed if it
//! leaks, and nothing bills by the request beyond free-tier noise. The right
//! response to a leak is to rotate it, not to panic.

/// Header CloudFront attaches to origin requests.
pub const ORIGIN_HEADER: &str = "x-cairn-origin";

/// Compare a presented secret against the expected one.
///
/// The comparison is constant-time with respect to content. Over the public
/// internet a timing attack on string equality is close to unexploitable, so
/// this is not load-bearing, but it costs a handful of instructions and removes
/// the question from a reviewer's mind.
///
/// Length is compared first and therefore leaks, which is fine: the length is
/// fixed by configuration and is not a function of the secret's content.
pub fn secret_matches(expected: &str, presented: &str) -> bool {
    if expected.len() != presented.len() {
        return false;
    }

    let mut difference = 0u8;
    for (a, b) in expected.bytes().zip(presented.bytes()) {
        difference |= a ^ b;
    }

    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_secrets_match() {
        assert!(secret_matches("s3cr3t-value", "s3cr3t-value"));
    }

    #[test]
    fn different_secrets_do_not_match() {
        assert!(!secret_matches("s3cr3t-value", "s3cr3t-valuF"));
        assert!(!secret_matches("s3cr3t-value", "totally-other"));
    }

    #[test]
    fn length_mismatch_does_not_match() {
        assert!(!secret_matches("short", "short-but-longer"));
        assert!(!secret_matches("longer-than-that", "long"));
    }

    /// The case that matters most in practice: a caller who sends no header at
    /// all must be refused, not accidentally admitted by an empty comparison.
    #[test]
    fn empty_presented_secret_is_refused() {
        assert!(!secret_matches("s3cr3t-value", ""));
    }

    /// Guards against a future edit that "simplifies" the empty case into
    /// something permissive.
    #[test]
    fn empty_expected_secret_refuses_everything_real() {
        assert!(!secret_matches("", "anything"));
    }
}
