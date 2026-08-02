//! The event types and the single function that turns a request into a row.
//!
//! [`StoredEvent::build`] is the entire ingest pipeline: validate, reject bots,
//! normalize, hash, stamp. It is pure and synchronous, so the Lambda handler
//! around it does nothing but deserialize, call this, and write one item.
//!
//! Note what [`StoredEvent`] does not have: a field for an IP address. The
//! address is borrowed by [`EventContext`] for the duration of one call, fed
//! into the visitor hash, and dropped. There is no field to accidentally
//! serialize, no attribute to accidentally write, and no way for a future edit
//! to persist one without adding a field and deleting the test that checks for
//! it.

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, UtcOffset};

use crate::normalize;
use crate::privacy::{DailySalt, VisitorId};
use crate::ua::{Browser, DeviceClass, Os, UserAgent};

pub const MAX_SITE_LEN: usize = 128;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_URL_LEN: usize = 2048;

/// How long raw events live before DynamoDB's TTL reaper removes them.
///
/// The rollup Lambda folds them into aggregates within the hour, so this is
/// only a replay window for fixing a bad rollup. Keeping it short is both a
/// storage decision and a privacy one: aggregates cannot be un-aggregated,
/// so after a week there is nothing left to leak.
pub const RAW_EVENT_TTL_DAYS: i64 = 7;

/// What the tracker script posts to `/e`.
///
/// Field names are short because this is serialized by hand in a script that is
/// budgeted at one kilobyte, and it is sent on every pageview.
#[derive(Debug, Clone, Deserialize)]
pub struct RawEvent {
    /// Site identifier, from the `data-site` attribute on the script tag.
    pub site: String,
    /// Event name. Defaults to `pageview`; custom events reuse this field.
    #[serde(default = "default_event_name")]
    pub name: String,
    /// Full `location.href` at the time of the event.
    pub url: String,
    /// `document.referrer`, absent on direct navigation.
    #[serde(default)]
    pub referrer: Option<String>,
    /// Viewport width, used only to break device-classification ties.
    #[serde(default)]
    pub width: Option<u32>,
}

fn default_event_name() -> String {
    "pageview".to_string()
}

/// Everything the server knows that the browser did not tell it.
///
/// `ip` is a borrow with a lifetime, not an owned `String`, which is a small
/// deliberate signal: this value is passed through, not kept.
#[derive(Debug, Clone, Copy)]
pub struct EventContext<'a> {
    /// Visitor address, used for hashing and nothing else.
    pub ip: &'a str,
    /// Raw `User-Agent` header.
    pub user_agent: &'a str,
    /// Two-letter country from CloudFront's `CloudFront-Viewer-Country` header.
    pub country: Option<&'a str>,
    /// Server receive time.
    pub at: OffsetDateTime,
}

/// Why an event was not recorded.
///
/// [`Self::Bot`] is not really an error, it is the expected outcome for a large
/// share of traffic, and the handler answers `204` for it exactly as it does
/// for a success. Crawlers are not owed a diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("automated traffic")]
    Bot,
    #[error("field `{field}` is empty")]
    FieldEmpty { field: &'static str },
    #[error("field `{field}` exceeds {max} bytes")]
    FieldTooLong { field: &'static str, max: usize },
    #[error("`url` is not an absolute URL")]
    MalformedUrl,
}

/// One recorded event, exactly as it is written to DynamoDB and archived to S3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredEvent {
    pub site: String,
    pub name: String,
    pub path: String,
    pub referrer: Option<String>,
    pub country: Option<String>,
    pub browser: Browser,
    pub os: Os,
    pub device: DeviceClass,
    pub visitor: VisitorId,
    /// UTC hour bucket, `YYYY-MM-DDTHH`. Doubles as the partition suffix.
    pub bucket: String,
    pub ts_millis: i64,
    /// Unix seconds, read by DynamoDB's TTL.
    pub expires_at: i64,
}

impl StoredEvent {
    /// Validate, filter, normalize, and hash a single incoming event.
    pub fn build(
        raw: RawEvent,
        ctx: EventContext<'_>,
        salt: &DailySalt,
    ) -> Result<Self, EventError> {
        // Bot check first. It is the cheapest rejection and it discards a large
        // fraction of traffic, so nothing below should pay for work on requests
        // that are about to be dropped.
        let agent = UserAgent::parse(ctx.user_agent);
        if agent.is_bot() {
            return Err(EventError::Bot);
        }

        check_field("site", &raw.site, MAX_SITE_LEN)?;
        check_field("name", &raw.name, MAX_NAME_LEN)?;
        check_field("url", &raw.url, MAX_URL_LEN)?;

        let path = normalize::path_from_url(&raw.url).ok_or(EventError::MalformedUrl)?;

        // Scoped so the borrow of `raw.url` ends before `raw` is taken apart.
        let referrer = {
            let own_host = normalize::host_from_url(&raw.url).ok_or(EventError::MalformedUrl)?;
            raw.referrer
                .as_deref()
                .and_then(|r| normalize::referrer_host(r, own_host))
        };

        let visitor = VisitorId::new(salt, &raw.site, ctx.ip, ctx.user_agent);
        let at = ctx.at.to_offset(UtcOffset::UTC);

        Ok(Self {
            path,
            referrer,
            country: ctx.country.and_then(normalize_country),
            browser: agent.browser(),
            os: agent.os(),
            device: agent.device(raw.width),
            visitor,
            bucket: hour_bucket(at),
            ts_millis: (at.unix_timestamp_nanos() / 1_000_000) as i64,
            expires_at: (at + Duration::days(RAW_EVENT_TTL_DAYS)).unix_timestamp(),
            site: raw.site,
            name: raw.name,
        })
    }

    /// DynamoDB partition key.
    ///
    /// Partitioning by site and hour keeps any single partition small and lets
    /// the rollup read a whole hour with one `Query` instead of a `Scan`.
    pub fn partition_key(&self) -> String {
        format!("E#{}#{}", self.site, self.bucket)
    }

    /// DynamoDB sort key.
    ///
    /// The timestamp is zero-padded so that lexicographic order, which is the
    /// only order DynamoDB sorts by, matches chronological order. Without the
    /// padding a shorter timestamp would sort before a longer one regardless of
    /// its value. The nonce breaks ties between events landing in the same
    /// millisecond, which would otherwise silently overwrite each other.
    pub fn sort_key(&self, nonce: &str) -> String {
        format!("{:013}#{}", self.ts_millis, nonce)
    }

    /// The `YYYY-MM-DD` prefix of the hour bucket, for daily aggregate keys.
    pub fn day(&self) -> &str {
        &self.bucket[..10]
    }
}

fn check_field(field: &'static str, value: &str, max: usize) -> Result<(), EventError> {
    if value.trim().is_empty() {
        return Err(EventError::FieldEmpty { field });
    }
    if value.len() > max {
        return Err(EventError::FieldTooLong { field, max });
    }
    Ok(())
}

/// Accept only a plausible ISO 3166-1 alpha-2 code.
///
/// CloudFront sends `ZZ` when it cannot resolve a country, which is a real
/// value in the header but not a real place, so it becomes `None` rather than
/// a country named "ZZ" ranking on the dashboard.
fn normalize_country(code: &str) -> Option<String> {
    let code = code.trim();
    if code.len() == 2
        && code.chars().all(|c| c.is_ascii_alphabetic())
        && !code.eq_ignore_ascii_case("zz")
    {
        Some(code.to_ascii_uppercase())
    } else {
        None
    }
}

fn hour_bucket(at: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}",
        at.year(),
        at.month() as u8,
        at.day(),
        at.hour()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month};

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    const IP: &str = "203.0.113.7";

    fn salt() -> DailySalt {
        DailySalt::derive(
            b"test-secret",
            Date::from_calendar_date(2026, Month::August, 2).unwrap(),
        )
    }

    fn at() -> OffsetDateTime {
        Date::from_calendar_date(2026, Month::August, 2)
            .unwrap()
            .with_hms_milli(14, 30, 15, 250)
            .unwrap()
            .assume_utc()
    }

    fn ctx<'a>(user_agent: &'a str, country: Option<&'a str>) -> EventContext<'a> {
        EventContext {
            ip: IP,
            user_agent,
            country,
            at: at(),
        }
    }

    fn raw() -> RawEvent {
        RawEvent {
            site: "gautamstar.github.io".to_string(),
            name: "pageview".to_string(),
            url: "https://gautamstar.github.io/portfolio/?utm_source=hn".to_string(),
            referrer: Some("https://news.ycombinator.com/item?id=1".to_string()),
            width: Some(1920),
        }
    }

    #[test]
    fn builds_a_complete_event() {
        let ev = StoredEvent::build(raw(), ctx(CHROME, Some("CA")), &salt()).unwrap();

        assert_eq!(ev.site, "gautamstar.github.io");
        assert_eq!(ev.name, "pageview");
        assert_eq!(ev.path, "/portfolio");
        assert_eq!(ev.referrer.as_deref(), Some("news.ycombinator.com"));
        assert_eq!(ev.country.as_deref(), Some("CA"));
        assert_eq!(ev.browser, Browser::Chrome);
        assert_eq!(ev.os, Os::Windows);
        assert_eq!(ev.device, DeviceClass::Desktop);
        assert_eq!(ev.bucket, "2026-08-02T14");
        assert_eq!(ev.day(), "2026-08-02");
    }

    #[test]
    fn bots_are_rejected_before_anything_else() {
        let err = StoredEvent::build(raw(), ctx("Googlebot/2.1", None), &salt()).unwrap_err();
        assert_eq!(err, EventError::Bot);
    }

    #[test]
    fn empty_fields_are_rejected() {
        let mut r = raw();
        r.site = "  ".to_string();
        assert_eq!(
            StoredEvent::build(r, ctx(CHROME, None), &salt()).unwrap_err(),
            EventError::FieldEmpty { field: "site" }
        );
    }

    #[test]
    fn oversized_fields_are_rejected() {
        let mut r = raw();
        r.url = format!("https://a.dev/{}", "x".repeat(MAX_URL_LEN));
        assert_eq!(
            StoredEvent::build(r, ctx(CHROME, None), &salt()).unwrap_err(),
            EventError::FieldTooLong {
                field: "url",
                max: MAX_URL_LEN
            }
        );
    }

    #[test]
    fn relative_urls_are_rejected() {
        let mut r = raw();
        r.url = "/portfolio".to_string();
        assert_eq!(
            StoredEvent::build(r, ctx(CHROME, None), &salt()).unwrap_err(),
            EventError::MalformedUrl
        );
    }

    #[test]
    fn internal_referrers_are_dropped() {
        let mut r = raw();
        r.referrer = Some("https://gautamstar.github.io/portfolio/other".to_string());
        let ev = StoredEvent::build(r, ctx(CHROME, None), &salt()).unwrap();
        assert_eq!(ev.referrer, None);
    }

    #[test]
    fn unknown_country_becomes_none() {
        let ev = StoredEvent::build(raw(), ctx(CHROME, Some("ZZ")), &salt()).unwrap();
        assert_eq!(ev.country, None);

        let ev = StoredEvent::build(raw(), ctx(CHROME, Some("bogus")), &salt()).unwrap();
        assert_eq!(ev.country, None);
    }

    #[test]
    fn country_is_uppercased() {
        let ev = StoredEvent::build(raw(), ctx(CHROME, Some("ca")), &salt()).unwrap();
        assert_eq!(ev.country.as_deref(), Some("CA"));
    }

    #[test]
    fn keys_are_shaped_for_dynamodb() {
        let ev = StoredEvent::build(raw(), ctx(CHROME, None), &salt()).unwrap();
        assert_eq!(ev.partition_key(), "E#gautamstar.github.io#2026-08-02T14");

        let sk = ev.sort_key("a1b2");
        assert!(sk.ends_with("#a1b2"));
        // Zero padding is what keeps lexicographic order chronological.
        assert_eq!(sk.split('#').next().unwrap().len(), 13);
    }

    #[test]
    fn sort_keys_order_chronologically_as_strings() {
        let mut early = StoredEvent::build(raw(), ctx(CHROME, None), &salt()).unwrap();
        let mut late = early.clone();
        early.ts_millis = 999;
        late.ts_millis = 1_000;
        assert!(
            early.sort_key("a") < late.sort_key("a"),
            "string order must track time order"
        );
    }

    #[test]
    fn ttl_is_seven_days_out() {
        let ev = StoredEvent::build(raw(), ctx(CHROME, None), &salt()).unwrap();
        let seconds = ev.expires_at - (ev.ts_millis / 1000);
        assert_eq!(seconds, RAW_EVENT_TTL_DAYS * 24 * 60 * 60);
    }

    #[test]
    fn name_defaults_to_pageview() {
        let r: RawEvent =
            serde_json::from_str(r#"{"site":"a.dev","url":"https://a.dev/x"}"#).unwrap();
        assert_eq!(r.name, "pageview");
        assert_eq!(r.referrer, None);
        assert_eq!(r.width, None);
    }

    /// The privacy guarantee, asserted rather than promised. If someone later
    /// adds an `ip` field to `StoredEvent`, this test is what stops it.
    #[test]
    fn nothing_that_gets_persisted_contains_the_ip() {
        let ev = StoredEvent::build(raw(), ctx(CHROME, Some("CA")), &salt()).unwrap();

        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains(IP), "raw IP must never reach storage");
        assert!(!json.contains("\"ip\""), "there must be no ip field at all");

        // The Debug rendering is what ends up in a tracing span or a panic
        // message, so it has to be clean too.
        assert!(!format!("{ev:?}").contains(IP));
    }

    /// Query strings are dropped before storage, so tokens and addresses that
    /// happen to be in a URL cannot be persisted.
    #[test]
    fn query_strings_never_reach_storage() {
        let mut r = raw();
        r.url = "https://a.dev/reset?token=hunter2&email=me@example.com".to_string();
        let ev = StoredEvent::build(r, ctx(CHROME, None), &salt()).unwrap();

        assert_eq!(ev.path, "/reset");
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("me@example.com"));
    }
}
