//! URL and referrer normalization.
//!
//! Two jobs, one of which is a privacy job.
//!
//! The obvious one is grouping: `/about`, `/about/`, and `/about?utm_source=x`
//! are one page, and a dashboard that lists them as three rows is useless.
//!
//! The less obvious one is that query strings are where personal data hides.
//! Password reset tokens, session IDs, email addresses in `?email=`, and the
//! entire UTM parameter family all live there, and storing raw URLs would
//! quietly recreate the tracking database this project exists to avoid. Cairn
//! drops the query string before anything is written, so there is no path by
//! which it could be persisted.
//!
//! Hand-rolled rather than using the `url` crate, which pulls in `idna` and its
//! Unicode tables. That is a large fraction of a megabyte of binary for parsing
//! that only ever needs a host and a path.

/// Longest path stored. Anything longer is truncated rather than rejected,
/// since a pathological URL should not cost a pageview.
pub const MAX_PATH_LEN: usize = 512;

/// Extract the normalized path from an absolute URL.
///
/// Returns `None` for input that is not an absolute URL, which is the tracker
/// misbehaving rather than something worth guessing about.
pub fn path_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;

    // Everything from the first delimiter onward. No delimiter at all means the
    // URL was bare like `https://example.com`, which is the root path.
    let Some(delimiter) = after_scheme.find(['/', '?', '#']) else {
        return Some("/".to_string());
    };
    let rest = &after_scheme[delimiter..];

    // A `?` or `#` before any `/` also means root, as in `https://x.com?a=1`.
    let path = if let Some(stripped) = rest.strip_prefix('/') {
        let end = stripped.find(['?', '#']).unwrap_or(stripped.len());
        &rest[..=end]
    } else {
        "/"
    };

    let path = truncate_on_char_boundary(path, MAX_PATH_LEN);

    // Collapse the trailing slash so `/about` and `/about/` are one row, but
    // leave the root alone: `/` must not become the empty string.
    let trimmed = path.trim_end_matches('/');
    Some(if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    })
}

/// Extract the bare host from an absolute URL, lowercased and without `www.`.
pub fn host_from_url(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];

    // Drop any `user:pass@` prefix. Credentials in a referrer are rare and
    // obviously must never be stored.
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    // Drop the port, taking care not to mangle a bracketed IPv6 literal. In
    // `[::1]:8080` the last colon is the port; in `[::1]` it is part of the
    // address, which is what the bracket check distinguishes.
    let host = match host.rfind(':') {
        Some(i) if !host[i + 1..].contains(']') => &host[..i],
        _ => host,
    };

    if host.is_empty() { None } else { Some(host) }
}

/// Reduce a referrer to the bare host worth showing on a dashboard.
///
/// Returns `None` when the referrer is absent, unparseable, or points at the
/// site itself. That last case is the important one: without it, internal
/// navigation makes every site its own top referrer, which is both useless and
/// the single most common bug in homegrown analytics.
pub fn referrer_host(referrer: &str, own_host: &str) -> Option<String> {
    let raw = host_from_url(referrer)?.to_ascii_lowercase();
    let host = strip_www(&raw);

    let own_raw = own_host.to_ascii_lowercase();
    let own = strip_www(&own_raw);

    if host.is_empty() || host == own {
        None
    } else {
        Some(host.to_string())
    }
}

/// `www.example.com` and `example.com` are the same origin to a reader.
fn strip_www(host: &str) -> &str {
    host.strip_prefix("www.").unwrap_or(host)
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
///
/// Slicing a `&str` at an arbitrary byte index panics if it lands mid-character,
/// and paths do contain multi-byte characters once a site has non-ASCII slugs.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_paths() {
        assert_eq!(
            path_from_url("https://a.dev/about").as_deref(),
            Some("/about")
        );
        assert_eq!(
            path_from_url("https://a.dev/blog/post-1").as_deref(),
            Some("/blog/post-1")
        );
    }

    #[test]
    fn bare_origin_is_root() {
        assert_eq!(path_from_url("https://a.dev").as_deref(), Some("/"));
        assert_eq!(path_from_url("https://a.dev/").as_deref(), Some("/"));
    }

    /// The privacy-relevant case: query strings carry tokens, emails, and
    /// session IDs, and none of it may survive into storage.
    #[test]
    fn query_strings_are_dropped() {
        assert_eq!(
            path_from_url("https://a.dev/reset?token=super-secret&email=me@example.com").as_deref(),
            Some("/reset")
        );
        assert_eq!(
            path_from_url("https://a.dev/?utm_source=newsletter").as_deref(),
            Some("/")
        );
    }

    #[test]
    fn fragments_are_dropped() {
        assert_eq!(
            path_from_url("https://a.dev/docs#installation").as_deref(),
            Some("/docs")
        );
        assert_eq!(path_from_url("https://a.dev#top").as_deref(), Some("/"));
    }

    #[test]
    fn trailing_slashes_collapse_but_root_survives() {
        assert_eq!(
            path_from_url("https://a.dev/about/").as_deref(),
            Some("/about")
        );
        assert_eq!(
            path_from_url("https://a.dev/about///").as_deref(),
            Some("/about")
        );
        assert_eq!(path_from_url("https://a.dev/").as_deref(), Some("/"));
    }

    #[test]
    fn rejects_input_that_is_not_an_absolute_url() {
        assert_eq!(path_from_url("/just/a/path"), None);
        assert_eq!(path_from_url(""), None);
    }

    #[test]
    fn long_paths_truncate_without_panicking_on_utf8() {
        // Multi-byte characters straddling the cutoff would panic a naive slice.
        let url = format!("https://a.dev/{}", "é".repeat(MAX_PATH_LEN));
        let path = path_from_url(&url).expect("absolute url");
        assert!(path.len() <= MAX_PATH_LEN);
    }

    #[test]
    fn extracts_hosts() {
        assert_eq!(host_from_url("https://a.dev/x"), Some("a.dev"));
        assert_eq!(host_from_url("http://a.dev"), Some("a.dev"));
        assert_eq!(host_from_url("https://a.dev:8443/x"), Some("a.dev"));
        assert_eq!(host_from_url("https://user:pw@a.dev/x"), Some("a.dev"));
    }

    #[test]
    fn ipv6_hosts_keep_their_colons() {
        assert_eq!(host_from_url("http://[::1]:8080/x"), Some("[::1]"));
        assert_eq!(host_from_url("http://[::1]/x"), Some("[::1]"));
    }

    /// Without this, every site becomes its own top referrer and the panel is
    /// worthless.
    #[test]
    fn internal_navigation_is_not_a_referrer() {
        assert_eq!(referrer_host("https://a.dev/prev", "a.dev"), None);
        assert_eq!(referrer_host("https://www.a.dev/prev", "a.dev"), None);
        assert_eq!(referrer_host("https://a.dev/prev", "www.a.dev"), None);
    }

    #[test]
    fn external_referrers_reduce_to_host() {
        assert_eq!(
            referrer_host("https://www.google.com/search?q=rust+lambda", "a.dev").as_deref(),
            Some("google.com")
        );
        assert_eq!(
            referrer_host("https://news.ycombinator.com/item?id=1", "a.dev").as_deref(),
            Some("news.ycombinator.com")
        );
    }

    #[test]
    fn unparseable_referrers_are_dropped() {
        assert_eq!(referrer_host("", "a.dev"), None);
        assert_eq!(referrer_host("android-app", "a.dev"), None);
    }

    #[test]
    fn referrer_matching_ignores_case() {
        assert_eq!(referrer_host("https://A.DEV/prev", "a.dev"), None);
        assert_eq!(
            referrer_host("https://GOOGLE.com/", "a.dev").as_deref(),
            Some("google.com")
        );
    }
}
