//! The dashboard's read API: `GET /api/stats/{site}?days=N`.
//!
//! Reads only the aggregate items the rollup wrote, never the raw events, with
//! one exception: the live visitor count, which by definition cannot come from
//! an hourly rollup.
//!
//! # Why multi-day visitor counts are sums, not true uniques
//!
//! Over a range this returns the *sum of each day's* unique visitors, so
//! someone who visits on Monday and Tuesday counts twice.
//!
//! That is not a shortcut, it is forced by the privacy design and cannot be
//! fixed without giving that design up. Visitor IDs are keyed by a salt that
//! rotates every midnight, so Monday's ID and Tuesday's ID for the same person
//! are unrelated values, and nothing retained anywhere can connect them. A
//! tool that reports true weekly uniques is necessarily holding an identifier
//! that outlives the day, which is exactly the thing Cairn refuses to keep.
//!
//! The honest framing for the dashboard is that daily numbers are exact and
//! range numbers are daily figures added up.

use std::collections::{BTreeMap, HashMap};

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::types::AttributeValue;
use cairn_core::aggregate::{self, Dimension};
use lambda_http::{Body, Error, Request, RequestExt, Response, run, service_fn};
use serde::Serialize;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// Entries returned per ranked panel.
const TOP_N: usize = 10;
/// A visitor counts as "live" if they have been seen within this window.
const LIVE_WINDOW_MINUTES: i64 = 5;
const DEFAULT_DAYS: u32 = 7;
const MAX_DAYS: u32 = 90;

struct App {
    dynamo: aws_sdk_dynamodb::Client,
    table: String,
}

impl App {
    async fn init() -> Result<Self, Error> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let table = std::env::var("CAIRN_TABLE")
            .map_err(|_| "CAIRN_TABLE must be set to the DynamoDB table name")?;

        Ok(Self {
            dynamo: aws_sdk_dynamodb::Client::new(&config),
            table,
        })
    }
}

#[derive(Debug, Serialize)]
struct Stats {
    site: String,
    from: String,
    to: String,
    /// Distinct visitors seen in the last five minutes.
    live: usize,
    views: u64,
    /// Sum of daily uniques. See the module docs for why this is not a true
    /// range-wide unique count.
    visitors: u64,
    series: Vec<DayPoint>,
    /// Hourly shape of the most recent day in the range.
    hours: Vec<HourPoint>,
    #[serde(flatten)]
    breakdowns: BTreeMap<&'static str, Vec<Entry>>,
}

#[derive(Debug, Serialize)]
struct DayPoint {
    date: String,
    views: u64,
    visitors: u64,
}

#[derive(Debug, Serialize)]
struct HourPoint {
    hour: u8,
    views: u64,
    visitors: u64,
}

#[derive(Debug, Serialize)]
struct Entry {
    name: String,
    views: u64,
    visitors: u64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_current_span(false)
        .with_target(false)
        .without_time()
        .init();

    let app = Arc::new(App::init().await?);

    run(service_fn(move |request: Request| {
        let app = Arc::clone(&app);
        async move { handle(app, request).await }
    }))
    .await
}

async fn handle(app: Arc<App>, request: Request) -> Result<Response<Body>, Error> {
    let Some(site) = site_from_path(request.uri().path()) else {
        return Ok(json_response(
            400,
            &serde_json::json!({ "error": "missing site" }),
        ));
    };

    let days = request
        .query_string_parameters_ref()
        .and_then(|params| params.first("days"))
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_DAYS)
        .clamp(1, MAX_DAYS);

    let stats = collect(&app, &site, days, OffsetDateTime::now_utc()).await?;
    Ok(json_response(200, &stats))
}

/// The site is the final path segment of `/api/stats/{site}`.
fn site_from_path(path: &str) -> Option<String> {
    let site = path.rsplit('/').find(|segment| !segment.is_empty())?;
    if site == "stats" || site == "api" {
        return None;
    }
    Some(site.to_string())
}

async fn collect(app: &App, site: &str, days: u32, now: OffsetDateTime) -> Result<Stats, Error> {
    let dates = day_range(now, days);

    let mut series = Vec::with_capacity(dates.len());
    let mut hours_by_day: HashMap<String, Vec<HourPoint>> = HashMap::new();
    let mut totals: HashMap<(Dimension, String), (u64, u64)> = HashMap::new();
    let mut views = 0u64;
    let mut visitors = 0u64;

    for date in &dates {
        let items = read_day(app, site, date).await?;

        // A day with no traffic still gets a zero point, so the chart has a
        // continuous x-axis instead of silently closing the gap.
        let mut day_point = DayPoint {
            date: date.clone(),
            views: 0,
            visitors: 0,
        };
        let mut hours = Vec::new();

        for (sort_key, counts) in items {
            if sort_key == aggregate::TOTAL_KEY {
                day_point.views = counts.0;
                day_point.visitors = counts.1;
            } else if let Some(hour) = aggregate::parse_hour(&sort_key) {
                hours.push(HourPoint {
                    hour,
                    views: counts.0,
                    visitors: counts.1,
                });
            } else if let Some((dimension, value)) = Dimension::parse(&sort_key) {
                let entry = totals.entry((dimension, value.to_string())).or_default();
                entry.0 += counts.0;
                entry.1 += counts.1;
            }
        }

        hours.sort_by_key(|point| point.hour);
        hours_by_day.insert(date.clone(), hours);

        views += day_point.views;
        visitors += day_point.visitors;
        series.push(day_point);
    }

    let mut breakdowns: BTreeMap<&'static str, Vec<Entry>> = BTreeMap::new();
    for dimension in Dimension::ALL {
        let mut entries: Vec<Entry> = totals
            .iter()
            .filter(|((kind, _), _)| *kind == dimension)
            .map(|((_, value), counts)| Entry {
                name: value.clone(),
                views: counts.0,
                visitors: counts.1,
            })
            .collect();

        // Ties broken by name so the panel does not reshuffle between requests
        // for entries with equal counts, which reads as flicker.
        entries.sort_by(|a, b| b.views.cmp(&a.views).then_with(|| a.name.cmp(&b.name)));
        entries.truncate(TOP_N);

        breakdowns.insert(dimension.json_field(), entries);
    }

    let latest = dates.last().cloned().unwrap_or_default();

    Ok(Stats {
        site: site.to_string(),
        from: dates.first().cloned().unwrap_or_default(),
        to: latest.clone(),
        live: live_visitors(app, site, now).await?,
        views,
        visitors,
        series,
        hours: hours_by_day.remove(&latest).unwrap_or_default(),
        breakdowns,
    })
}

/// Read one day's aggregate items as `(sort_key, (views, visitors))`.
async fn read_day(app: &App, site: &str, date: &str) -> Result<Vec<(String, (u64, u64))>, Error> {
    let partition = aggregate::partition_key(site, date);
    let mut rows = Vec::new();
    let mut start_key = None;

    loop {
        let response = app
            .dynamo
            .query()
            .table_name(&app.table)
            .key_condition_expression("pk = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(partition.clone()))
            .set_exclusive_start_key(start_key.take())
            .send()
            .await?;

        for item in response.items() {
            let Some(sort_key) = item.get("sk").and_then(|v| v.as_s().ok()) else {
                continue;
            };
            rows.push((sort_key.clone(), (number(item, "vw"), number(item, "vi"))));
        }

        start_key = response.last_evaluated_key().cloned();
        if start_key.is_none() {
            break;
        }
    }

    Ok(rows)
}

/// Count distinct visitors seen in the last few minutes.
///
/// This is the one read that touches raw events, because an hourly rollup
/// cannot answer a question about the last five minutes.
///
/// It is cheap because of how the ingest sort key was built. Raw sort keys are
/// `{millis:013}#{nonce}`, zero-padded, so a cutoff timestamp padded the same
/// way is a valid *key condition* rather than a filter. DynamoDB seeks straight
/// to the offset and reads only matching items, where a filter expression would
/// read the whole partition and charge for all of it before discarding rows.
async fn live_visitors(app: &App, site: &str, now: OffsetDateTime) -> Result<usize, Error> {
    let cutoff = now - Duration::minutes(LIVE_WINDOW_MINUTES);
    let cutoff_millis = (cutoff.unix_timestamp_nanos() / 1_000_000) as i64;

    let mut seen = std::collections::HashSet::new();

    // The window can straddle an hour boundary, and each hour is its own
    // partition, so both have to be asked.
    for at in [cutoff, now] {
        let partition = format!(
            "E#{site}#{:04}-{:02}-{:02}T{:02}",
            at.year(),
            at.month() as u8,
            at.day(),
            at.hour()
        );

        let response = app
            .dynamo
            .query()
            .table_name(&app.table)
            .key_condition_expression("pk = :pk AND sk >= :cutoff")
            .expression_attribute_values(":pk", AttributeValue::S(partition))
            .expression_attribute_values(
                ":cutoff",
                AttributeValue::S(format!("{cutoff_millis:013}")),
            )
            // `vi` is not a DynamoDB reserved word, but aliasing costs nothing
            // and removes the question.
            .projection_expression("#v")
            .expression_attribute_names("#v", "vi")
            .send()
            .await?;

        for item in response.items() {
            if let Some(visitor) = item.get("vi").and_then(|v| v.as_s().ok()) {
                seen.insert(visitor.clone());
            }
        }
    }

    Ok(seen.len())
}

fn number(item: &HashMap<String, AttributeValue>, key: &str) -> u64 {
    item.get(key)
        .and_then(|value| value.as_n().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// The `days` dates ending today, oldest first.
fn day_range(now: OffsetDateTime, days: u32) -> Vec<String> {
    (0..days)
        .rev()
        .map(|offset| {
            let at = now - Duration::days(i64::from(offset));
            format!("{:04}-{:02}-{:02}", at.year(), at.month() as u8, at.day())
        })
        .collect()
}

fn json_response<T: Serialize>(status: u16, payload: &T) -> Response<Body> {
    let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".to_string());

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        // Let CloudFront absorb repeat loads. A minute of staleness is
        // invisible on a daily chart and removes most Lambda invocations from
        // someone leaving the dashboard open.
        .header("cache-control", "public, max-age=60")
        .body(Body::from(body))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month};

    fn at(day: u8, hour: u8) -> OffsetDateTime {
        Date::from_calendar_date(2026, Month::August, day)
            .unwrap()
            .with_hms(hour, 30, 0)
            .unwrap()
            .assume_utc()
    }

    #[test]
    fn extracts_site_from_path() {
        assert_eq!(
            site_from_path("/api/stats/gautamstar.github.io").as_deref(),
            Some("gautamstar.github.io")
        );
        // A trailing slash must not swallow the site.
        assert_eq!(
            site_from_path("/api/stats/a.dev/").as_deref(),
            Some("a.dev")
        );
    }

    #[test]
    fn rejects_paths_with_no_site() {
        assert_eq!(site_from_path("/api/stats"), None);
        assert_eq!(site_from_path("/api/stats/"), None);
        assert_eq!(site_from_path("/"), None);
    }

    #[test]
    fn day_range_is_oldest_first_and_includes_today() {
        let range = day_range(at(3, 12), 3);
        assert_eq!(range, ["2026-08-01", "2026-08-02", "2026-08-03"]);
    }

    #[test]
    fn single_day_range_is_just_today() {
        assert_eq!(day_range(at(3, 12), 1), ["2026-08-03"]);
    }

    /// The live window straddles midnight and month boundaries, which is where
    /// naive date arithmetic breaks.
    #[test]
    fn day_range_crosses_month_boundaries() {
        let range = day_range(at(2, 0), 3);
        assert_eq!(range, ["2026-07-31", "2026-08-01", "2026-08-02"]);
    }

    #[test]
    fn entries_rank_by_views_then_name() {
        let mut entries = [
            Entry {
                name: "b".into(),
                views: 5,
                visitors: 5,
            },
            Entry {
                name: "a".into(),
                views: 5,
                visitors: 4,
            },
            Entry {
                name: "c".into(),
                views: 9,
                visitors: 1,
            },
        ];
        entries.sort_by(|a, b| b.views.cmp(&a.views).then_with(|| a.name.cmp(&b.name)));

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["c", "a", "b"]);
    }

    #[test]
    fn breakdown_field_names_match_the_dimensions() {
        // Guards the dashboard's contract: every dimension must surface under a
        // key the front end can read.
        for dimension in Dimension::ALL {
            assert!(!dimension.json_field().is_empty());
        }
    }
}
