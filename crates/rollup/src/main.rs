//! Hourly aggregation, run on an EventBridge schedule.
//!
//! Reads the raw event rows the ingest handler wrote, folds them into the
//! aggregate items the dashboard reads, and archives the raw NDJSON to S3
//! before DynamoDB's TTL removes it.
//!
//! # Recompute, do not increment
//!
//! The obvious design is to add each new event to a running counter with
//! `UpdateItem ... ADD`. This handler deliberately does not. Incrementing is
//! only correct if every event is counted exactly once, forever, which means a
//! cron that fires twice, a run that dies halfway through, or a manual replay
//! all silently inflate the numbers with no way to tell afterwards. There is no
//! way to audit a counter that drifted.
//!
//! Instead every run recomputes whole days from the raw rows and overwrites the
//! aggregates. That makes the job idempotent: running it once, twice, or ten
//! times produces the same result, a failed run needs no cleanup, and fixing a
//! bug is a re-run rather than a migration. It costs more reads, which at this
//! traffic level is a rounding error against the DynamoDB free tier.
//!
//! Both today and yesterday are recomputed on every run, because a run at
//! 00:15 would otherwise leave the previous day's final hour permanently
//! missing the events that arrived after the last run of that day.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::types::{AttributeValue, PutRequest, WriteRequest};
use aws_sdk_s3::primitives::ByteStream;
use cairn_core::aggregate::{self, Dimension};
use lambda_runtime::{Error, LambdaEvent, run, service_fn};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

/// DynamoDB's hard limit on a single `BatchWriteItem`.
const BATCH_SIZE: usize = 25;
/// Attempts before giving up on capacity-throttled writes.
const MAX_WRITE_ATTEMPTS: u32 = 6;

struct App {
    dynamo: aws_sdk_dynamodb::Client,
    s3: aws_sdk_s3::Client,
    table: String,
    archive_bucket: Option<String>,
    sites: Vec<String>,
}

impl App {
    async fn init() -> Result<Self, Error> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

        let table = std::env::var("CAIRN_TABLE")
            .map_err(|_| "CAIRN_TABLE must be set to the DynamoDB table name")?;

        // Seed list, for sites that predate the account system. Everything
        // registered since is discovered from the registry at run time, so
        // adding a customer does not mean a Terraform apply. Optional now: a
        // fresh deployment has no grandfathered sites.
        let sites = std::env::var("CAIRN_SITES")
            .unwrap_or_default()
            .split(',')
            .map(|site| site.trim().to_string())
            .filter(|site| !site.is_empty())
            .collect::<Vec<_>>();

        Ok(Self {
            dynamo: aws_sdk_dynamodb::Client::new(&config),
            s3: aws_sdk_s3::Client::new(&config),
            table,
            archive_bucket: std::env::var("CAIRN_ARCHIVE_BUCKET").ok(),
            sites,
        })
    }
}

/// The invocation payload.
///
/// EventBridge sends a scheduled event whose fields are all ignored, and serde
/// skips unknown fields, so the scheduled case deserializes to all-defaults.
/// The two overrides exist for manual backfills:
/// `{"days": ["2026-07-30"], "sites": ["a.dev"]}`.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RollupRequest {
    days: Option<Vec<String>>,
    sites: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct Summary {
    processed: Vec<DaySummary>,
}

#[derive(Debug, Serialize)]
struct DaySummary {
    site: String,
    day: String,
    events: usize,
    views: u64,
    visitors: usize,
    items_written: usize,
}

/// One raw event row, decoded back out of DynamoDB.
///
/// The field names match the two-character attribute names the ingest handler
/// writes; the serde renames are what make the S3 archive readable by anything
/// that is not this program.
#[derive(Debug, Serialize)]
struct Row {
    name: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    referrer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    browser: String,
    os: String,
    device: String,
    visitor: String,
    ts_millis: i64,
}

impl Row {
    /// Decode an item, or `None` if a required attribute is missing.
    ///
    /// A malformed row is skipped rather than failing the run. Losing one event
    /// to a decode bug is much better than a poison row that blocks every
    /// aggregate for that day from ever being written.
    fn from_item(item: &HashMap<String, AttributeValue>) -> Option<Self> {
        Some(Self {
            name: string(item, "nm")?,
            path: string(item, "pa")?,
            referrer: string(item, "rf"),
            country: string(item, "cy"),
            browser: string(item, "br")?,
            os: string(item, "os")?,
            device: string(item, "dv")?,
            visitor: string(item, "vi")?,
            ts_millis: number(item, "ts")?,
        })
    }
}

fn string(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key)?.as_s().ok().cloned()
}

fn number(item: &HashMap<String, AttributeValue>, key: &str) -> Option<i64> {
    item.get(key)?.as_n().ok()?.parse().ok()
}

/// Views and distinct visitors for one slice of a day.
#[derive(Default)]
struct Bucket {
    views: u64,
    visitors: HashSet<String>,
}

impl Bucket {
    fn record(&mut self, visitor: &str) {
        self.views += 1;
        // A `HashSet` is exact and cheap at this scale. It is also the part
        // that would have to become a HyperLogLog sketch somewhere north of a
        // million visitors a day, when holding every ID in memory stops being
        // reasonable.
        self.visitors.insert(visitor.to_string());
    }
}

#[derive(Default)]
struct Aggregate {
    day: Bucket,
    hours: BTreeMap<u8, Bucket>,
    dimensions: HashMap<(Dimension, String), Bucket>,
}

impl Aggregate {
    fn record(&mut self, row: &Row, hour: u8) {
        // Custom events are counted only against their own dimension. Letting
        // them raise the view count would make "pageviews" mean "pageviews plus
        // whatever the site decided to instrument", which is not comparable
        // across sites or across time.
        if row.name != "pageview" {
            self.dimension(Dimension::Event, &row.name, &row.visitor);
            return;
        }

        self.day.record(&row.visitor);
        self.hours.entry(hour).or_default().record(&row.visitor);

        self.dimension(Dimension::Path, &row.path, &row.visitor);
        self.dimension(Dimension::Browser, &row.browser, &row.visitor);
        self.dimension(Dimension::Os, &row.os, &row.visitor);
        self.dimension(Dimension::Device, &row.device, &row.visitor);

        if let Some(referrer) = &row.referrer {
            self.dimension(Dimension::Referrer, referrer, &row.visitor);
        }
        if let Some(country) = &row.country {
            self.dimension(Dimension::Country, country, &row.visitor);
        }
    }

    fn dimension(&mut self, dimension: Dimension, value: &str, visitor: &str) {
        self.dimensions
            .entry((dimension, value.to_string()))
            .or_default()
            .record(visitor);
    }

    fn items(&self, site: &str, day: &str) -> Vec<HashMap<String, AttributeValue>> {
        let partition = aggregate::partition_key(site, day);

        let mut items = vec![aggregate_item(&partition, aggregate::TOTAL_KEY, &self.day)];

        for (hour, bucket) in &self.hours {
            items.push(aggregate_item(
                &partition,
                &aggregate::hour_key(*hour),
                bucket,
            ));
        }
        for ((dimension, value), bucket) in &self.dimensions {
            items.push(aggregate_item(&partition, &dimension.key(value), bucket));
        }

        items
    }
}

fn aggregate_item(partition: &str, sort: &str, bucket: &Bucket) -> HashMap<String, AttributeValue> {
    HashMap::from([
        ("pk".to_string(), AttributeValue::S(partition.to_string())),
        ("sk".to_string(), AttributeValue::S(sort.to_string())),
        (
            "vw".to_string(),
            AttributeValue::N(bucket.views.to_string()),
        ),
        (
            "vi".to_string(),
            AttributeValue::N(bucket.visitors.len().to_string()),
        ),
    ])
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

    run(service_fn(move |event: LambdaEvent<RollupRequest>| {
        let app = Arc::clone(&app);
        async move { handle(app, event).await }
    }))
    .await
}

/// Every site this run should aggregate: the seed list plus the registry.
///
/// Deduplicated and sorted so a run is deterministic and a site that appears in
/// both is not rolled up twice.
async fn registered_sites(app: &App) -> Result<Vec<String>, Error> {
    let found = app
        .dynamo
        .get_item()
        .table_name(&app.table)
        .key(
            "pk",
            aws_sdk_dynamodb::types::AttributeValue::S(cairn_core::account::REGISTRY_PK.into()),
        )
        .key(
            "sk",
            aws_sdk_dynamodb::types::AttributeValue::S(cairn_core::account::REGISTRY_SK.into()),
        )
        .send()
        .await?;

    let mut sites: Vec<String> = app.sites.clone();
    if let Some(registered) = found
        .item()
        .and_then(|item| item.get("sites"))
        .and_then(|value| value.as_ss().ok())
    {
        sites.extend(registered.iter().cloned());
    }
    sites.sort();
    sites.dedup();
    Ok(sites)
}

async fn handle(app: Arc<App>, event: LambdaEvent<RollupRequest>) -> Result<Summary, Error> {
    let (request, _context) = event.into_parts();

    // An explicit list in the request wins, so a replay can target one site.
    let sites = match request.sites {
        Some(requested) => requested,
        None => registered_sites(&app).await?,
    };
    let days = request
        .days
        .unwrap_or_else(|| default_days(OffsetDateTime::now_utc()));

    let mut processed = Vec::new();
    for site in &sites {
        for day in &days {
            processed.push(rollup_day(&app, site, day).await?);
        }
    }

    Ok(Summary { processed })
}

/// Recompute one site-day from its raw rows.
async fn rollup_day(app: &App, site: &str, day: &str) -> Result<DaySummary, Error> {
    let mut aggregate = Aggregate::default();
    let mut events = 0usize;

    for hour in 0..24u8 {
        let rows = read_hour(app, site, day, hour).await?;
        if rows.is_empty() {
            continue;
        }

        events += rows.len();
        for row in &rows {
            aggregate.record(row, hour);
        }

        // Overwriting the same object every run is what keeps this idempotent.
        // The final write for a given hour is the complete one.
        archive_hour(app, site, day, hour, &rows).await?;
    }

    let items = aggregate.items(site, day);
    let items_written = items.len();
    write_items(app, items).await?;

    // Usage for plan limits. A plain overwrite, keyed by day: re-running a day
    // rewrites the same row with the same count instead of adding to it, which
    // is the same idempotency argument the aggregates rest on.
    write_usage(app, site, day, events, aggregate.day.views).await?;

    let summary = DaySummary {
        site: site.to_string(),
        day: day.to_string(),
        events,
        views: aggregate.day.views,
        visitors: aggregate.day.visitors.len(),
        items_written,
    };

    tracing::info!(
        site = %summary.site,
        day = %summary.day,
        events = summary.events,
        views = summary.views,
        visitors = summary.visitors,
        "rolled up day"
    );

    Ok(summary)
}

/// Read every raw row in one hour partition, following pagination.
async fn read_hour(app: &App, site: &str, day: &str, hour: u8) -> Result<Vec<Row>, Error> {
    let partition = format!("E#{site}#{day}T{hour:02}");
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
            match Row::from_item(item) {
                Some(row) => rows.push(row),
                None => tracing::warn!(partition = %partition, "skipping undecodable row"),
            }
        }

        start_key = response.last_evaluated_key().cloned();
        if start_key.is_none() {
            break;
        }
    }

    Ok(rows)
}

/// Write one hour of raw rows to S3 as NDJSON.
///
/// Newline-delimited JSON rather than Parquet on purpose: it is readable with
/// `zcat`, appendable, and queryable by Athena as-is. Parquet would be the
/// right answer at a volume this project does not have.
async fn archive_hour(
    app: &App,
    site: &str,
    day: &str,
    hour: u8,
    rows: &[Row],
) -> Result<(), Error> {
    let Some(bucket) = &app.archive_bucket else {
        return Ok(());
    };

    let mut body = String::new();
    for row in rows {
        body.push_str(&serde_json::to_string(row)?);
        body.push('\n');
    }

    // Hive-style partitioning, so Athena or DuckDB can prune on site and date
    // without a catalog.
    let key = format!("raw/site={site}/date={day}/hour={hour:02}.ndjson");

    app.s3
        .put_object()
        .bucket(bucket)
        .key(&key)
        .content_type("application/x-ndjson")
        .body(ByteStream::from(body.into_bytes()))
        .send()
        .await?;

    Ok(())
}

/// Write aggregates in batches, retrying whatever DynamoDB declines to take.
///
/// The table runs at 5 provisioned WCU to stay inside the perpetual free tier,
/// which is ample for ingest but easy to exceed in a burst of aggregate writes.
/// Record how many events a site produced on one day.
async fn write_usage(
    app: &App,
    site: &str,
    day: &str,
    events: usize,
    views: u64,
) -> Result<(), Error> {
    use aws_sdk_dynamodb::types::AttributeValue;

    app.dynamo
        .put_item()
        .table_name(&app.table)
        .item("pk", AttributeValue::S(cairn_core::account::usage_pk(site)))
        .item("sk", AttributeValue::S(day.to_string()))
        .item("events", AttributeValue::N(events.to_string()))
        .item("views", AttributeValue::N(views.to_string()))
        .send()
        .await?;
    Ok(())
}

/// `BatchWriteItem` does not fail on throttling, it returns the leftovers in
/// `unprocessed_items`, and dropping those on the floor would silently lose
/// panels from the dashboard.
async fn write_items(app: &App, items: Vec<HashMap<String, AttributeValue>>) -> Result<(), Error> {
    for chunk in items.chunks(BATCH_SIZE) {
        let mut pending = chunk
            .iter()
            .map(|item| {
                Ok(WriteRequest::builder()
                    .put_request(PutRequest::builder().set_item(Some(item.clone())).build()?)
                    .build())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        for attempt in 0..MAX_WRITE_ATTEMPTS {
            let response = app
                .dynamo
                .batch_write_item()
                .request_items(&app.table, pending.clone())
                .send()
                .await?;

            pending = response
                .unprocessed_items()
                .and_then(|items| items.get(&app.table))
                .cloned()
                .unwrap_or_default();

            if pending.is_empty() {
                break;
            }

            // Exponential backoff, which is the documented way to respond to
            // unprocessed items rather than hammering the same capacity.
            let delay = std::time::Duration::from_millis(50 << attempt);
            tracing::warn!(
                remaining = pending.len(),
                delay_ms = delay.as_millis(),
                "capacity exceeded, backing off"
            );
            tokio::time::sleep(delay).await;
        }

        if !pending.is_empty() {
            return Err(format!(
                "gave up after {MAX_WRITE_ATTEMPTS} attempts with {} items unwritten",
                pending.len()
            )
            .into());
        }
    }

    Ok(())
}

/// Yesterday and today, in UTC.
fn default_days(now: OffsetDateTime) -> Vec<String> {
    vec![format_day(now - Duration::days(1)), format_day(now)]
}

fn format_day(at: OffsetDateTime) -> String {
    format!("{:04}-{:02}-{:02}", at.year(), at.month() as u8, at.day())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month};

    fn row(name: &str, path: &str, visitor: &str) -> Row {
        Row {
            name: name.to_string(),
            path: path.to_string(),
            referrer: Some("google.com".to_string()),
            country: Some("CA".to_string()),
            browser: "Chrome".to_string(),
            os: "Windows".to_string(),
            device: "Desktop".to_string(),
            visitor: visitor.to_string(),
            ts_millis: 0,
        }
    }

    #[test]
    fn repeat_views_count_once_per_visitor() {
        let mut aggregate = Aggregate::default();
        aggregate.record(&row("pageview", "/", "alice"), 9);
        aggregate.record(&row("pageview", "/", "alice"), 9);
        aggregate.record(&row("pageview", "/", "bob"), 9);

        assert_eq!(aggregate.day.views, 3);
        assert_eq!(aggregate.day.visitors.len(), 2);
    }

    /// The distinction that keeps "views" comparable across sites.
    #[test]
    fn custom_events_do_not_inflate_views() {
        let mut aggregate = Aggregate::default();
        aggregate.record(&row("pageview", "/", "alice"), 9);
        aggregate.record(&row("signup", "/", "alice"), 9);

        assert_eq!(aggregate.day.views, 1);

        let events = aggregate
            .dimensions
            .get(&(Dimension::Event, "signup".to_string()))
            .expect("event recorded");
        assert_eq!(events.views, 1);

        // The custom event must not have added a second hit to the path panel.
        let pages = aggregate
            .dimensions
            .get(&(Dimension::Path, "/".to_string()))
            .expect("path recorded");
        assert_eq!(pages.views, 1);
    }

    #[test]
    fn hours_are_kept_separate() {
        let mut aggregate = Aggregate::default();
        aggregate.record(&row("pageview", "/", "alice"), 9);
        aggregate.record(&row("pageview", "/", "bob"), 14);

        assert_eq!(aggregate.hours.len(), 2);
        assert_eq!(aggregate.hours[&9].views, 1);
        assert_eq!(aggregate.hours[&14].views, 1);
    }

    #[test]
    fn absent_referrer_and_country_are_not_counted() {
        let mut sparse = row("pageview", "/", "alice");
        sparse.referrer = None;
        sparse.country = None;

        let mut aggregate = Aggregate::default();
        aggregate.record(&sparse, 9);

        assert!(
            !aggregate
                .dimensions
                .keys()
                .any(|(dimension, _)| *dimension == Dimension::Referrer
                    || *dimension == Dimension::Country)
        );
    }

    #[test]
    fn items_cover_totals_hours_and_dimensions() {
        let mut aggregate = Aggregate::default();
        aggregate.record(&row("pageview", "/about", "alice"), 9);

        let items = aggregate.items("a.dev", "2026-08-02");
        let sort_keys: Vec<String> = items
            .iter()
            .map(|item| item["sk"].as_s().unwrap().clone())
            .collect();

        assert!(sort_keys.contains(&aggregate::TOTAL_KEY.to_string()));
        assert!(sort_keys.contains(&"HOUR#09".to_string()));
        assert!(sort_keys.contains(&"PATH#/about".to_string()));
        assert!(sort_keys.contains(&"CTRY#CA".to_string()));

        for item in &items {
            assert_eq!(item["pk"].as_s().unwrap(), "A#a.dev#2026-08-02");
        }
    }

    #[test]
    fn undecodable_rows_are_skipped_not_fatal() {
        let mut item = HashMap::new();
        item.insert("pa".to_string(), AttributeValue::S("/".to_string()));
        // Missing every other required attribute.
        assert!(Row::from_item(&item).is_none());
    }

    #[test]
    fn default_days_covers_the_midnight_boundary() {
        let midnight_ish = Date::from_calendar_date(2026, Month::August, 2)
            .unwrap()
            .with_hms(0, 15, 0)
            .unwrap()
            .assume_utc();

        assert_eq!(default_days(midnight_ish), ["2026-08-01", "2026-08-02"]);
    }
}
