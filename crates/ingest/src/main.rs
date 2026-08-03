//! The ingest endpoint: `POST /e`.
//!
//! This is the hot path and the reason the project is written in Rust. It runs
//! on every pageview of every instrumented site, so the work is kept to the
//! minimum that still produces a correct row:
//!
//! 1. one allocation to lowercase the user agent,
//! 2. pure CPU work in `cairn-core` to filter, classify, normalize, and hash,
//! 3. exactly one DynamoDB `PutItem`.
//!
//! No S3 write, no counter update, no second round trip. Everything
//! dimensional (top pages, referrers, countries, unique visitors) is derived
//! later by the rollup Lambda from these rows, which keeps the latency a
//! visitor actually waits on down to a single network call.

use std::collections::HashMap;
use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::types::AttributeValue;
use cairn_core::{DailySalt, EventContext, EventError, RawEvent, StoredEvent};
use lambda_http::http::Method;
use lambda_http::request::RequestContext;
use lambda_http::{Body, Error, Request, RequestExt, Response, run, service_fn};
use time::OffsetDateTime;

/// Process-wide state, built once per execution environment and reused by every
/// warm invocation.
///
/// The SDK client and the hashing secret are the expensive things to obtain
/// (TLS setup and an SSM round trip respectively), so both happen during the
/// cold start rather than per request.
struct App {
    dynamo: aws_sdk_dynamodb::Client,
    table: String,
    secret: Vec<u8>,
    /// Shared secret CloudFront attaches to origin requests.
    ///
    /// `None` disables the check, which is only correct when nothing is in
    /// front of the handler. That is the local-testing case; Terraform always
    /// sets it in AWS.
    origin_secret: Option<String>,
}

impl App {
    async fn init() -> Result<Self, Error> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let table = std::env::var("CAIRN_TABLE")
            .map_err(|_| "CAIRN_TABLE must be set to the DynamoDB table name")?;
        let secret = load_secret(&config).await?;

        let origin_secret = std::env::var("CAIRN_ORIGIN_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
        if origin_secret.is_none() {
            tracing::warn!(
                "CAIRN_ORIGIN_SECRET is unset; the CloudFront-only check is DISABLED and \
                 visitor identification can be forged by calling the API directly"
            );
        }

        Ok(Self {
            dynamo: aws_sdk_dynamodb::Client::new(&config),
            table,
            secret,
            origin_secret,
        })
    }
}

/// Fetch the long-lived visitor-hashing secret.
///
/// In AWS this is an SSM SecureString, read once at cold start. Parameter Store
/// Standard tier is free, where Secrets Manager would be $0.40 per month for
/// one value that never rotates on its own.
///
/// `CAIRN_SECRET` short-circuits the lookup so the handler runs under
/// `cargo lambda watch` against DynamoDB Local with no AWS account at all. It
/// is a development convenience and the Terraform never sets it.
async fn load_secret(config: &aws_config::SdkConfig) -> Result<Vec<u8>, Error> {
    if let Ok(local) = std::env::var("CAIRN_SECRET") {
        tracing::warn!("using CAIRN_SECRET from the environment; this is for local development");
        return Ok(local.into_bytes());
    }

    let name = std::env::var("CAIRN_SECRET_PARAM")
        .map_err(|_| "CAIRN_SECRET_PARAM must be set to the SSM parameter name")?;

    let response = aws_sdk_ssm::Client::new(config)
        .get_parameter()
        .name(&name)
        .with_decryption(true)
        .send()
        .await?;

    let value = response
        .parameter()
        .and_then(|parameter| parameter.value())
        .ok_or("SSM parameter exists but has no value")?;

    Ok(value.as_bytes().to_vec())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    // JSON logs so CloudWatch Logs Insights can query fields directly, and no
    // timestamp because CloudWatch stamps every line already.
    tracing_subscriber::fmt()
        .json()
        .with_max_level(tracing::Level::INFO)
        .with_current_span(false)
        .with_target(false)
        .without_time()
        .init();

    // A single-threaded runtime is the right shape here: Lambda gives each
    // execution environment one request at a time, so a work-stealing scheduler
    // would add cold-start cost and thread overhead for concurrency that never
    // materializes.
    let app = Arc::new(App::init().await?);

    run(service_fn(move |request: Request| {
        let app = Arc::clone(&app);
        async move { handle(app, request).await }
    }))
    .await
}

async fn handle(app: Arc<App>, request: Request) -> Result<Response<Body>, Error> {
    // First, before anything else is trusted. API Gateway is publicly
    // reachable, and a request that skipped CloudFront carries no
    // CloudFront-Viewer-Address, which would send visitor identification down
    // the X-Forwarded-For fallback that the caller fully controls.
    //
    // 403 with no body and no explanation: a caller probing the endpoint learns
    // only that it refused.
    if let Some(expected) = &app.origin_secret {
        let presented = header(&request, cairn_core::ORIGIN_HEADER).unwrap_or_default();
        if !cairn_core::secret_matches(expected, presented) {
            return Ok(status_only(403));
        }
    }

    // sendBeacon posts `text/plain`, which is a CORS-simple request and so is
    // never preflighted. This arm exists for the fetch() fallback path in the
    // tracker, which can be preflighted on some browsers.
    if request.method() == Method::OPTIONS {
        return Ok(preflight());
    }
    if request.method() != Method::POST {
        return Ok(status_only(405));
    }

    let raw: RawEvent = match serde_json::from_slice(request.body().as_ref()) {
        Ok(event) => event,
        Err(error) => {
            // Worth a real status: this only happens if the tracker and the
            // handler disagree about the payload, which is a bug in one of them.
            tracing::debug!(%error, "malformed event payload");
            return Ok(status_only(400));
        }
    };

    let ip = client_ip(&request);
    let user_agent = header(&request, "user-agent").unwrap_or_default();
    let country = header(&request, "cloudfront-viewer-country");

    let now = OffsetDateTime::now_utc();

    // Derived per request rather than cached. BLAKE3 over a few dozen bytes is
    // on the order of a hundred nanoseconds, so a mutex-guarded day cache would
    // add contention and a branch to save less time than the lock itself costs.
    let salt = DailySalt::derive(&app.secret, now.date());

    let context = EventContext {
        ip: &ip,
        user_agent,
        country,
        at: now,
    };

    let event = match StoredEvent::build(raw, context, &salt) {
        Ok(event) => event,
        // Not an error. Roughly half of raw traffic is automated, and a crawler
        // gets the same 204 a person does: no diagnostic, nothing to probe.
        Err(EventError::Bot) => return Ok(no_content()),
        Err(error) => {
            tracing::debug!(%error, "rejected event");
            return Ok(status_only(400));
        }
    };

    // The Lambda request ID is unique per invocation and already in hand, which
    // makes it a free tiebreaker for two events landing in the same
    // millisecond. Without it the second would overwrite the first.
    let nonce = request.lambda_context().request_id;

    // Deliberately propagated rather than swallowed. Answering 204 on a failed
    // write would lose data silently and leave the Lambda error metric flat,
    // so there would be nothing to alarm on.
    app.dynamo
        .put_item()
        .table_name(&app.table)
        .set_item(Some(to_item(&event, &nonce)))
        .send()
        .await?;

    Ok(no_content())
}

/// Build the DynamoDB item.
///
/// Attribute names are two characters because DynamoDB bills write capacity on
/// the encoded size of the whole item, names included, rounded up to the next
/// kilobyte. Long names would be paid for on every single pageview forever.
fn to_item(event: &StoredEvent, nonce: &str) -> HashMap<String, AttributeValue> {
    let mut item = HashMap::from([
        ("pk".to_string(), AttributeValue::S(event.partition_key())),
        ("sk".to_string(), AttributeValue::S(event.sort_key(nonce))),
        ("st".to_string(), AttributeValue::S(event.site.clone())),
        ("nm".to_string(), AttributeValue::S(event.name.clone())),
        ("pa".to_string(), AttributeValue::S(event.path.clone())),
        (
            "br".to_string(),
            AttributeValue::S(event.browser.as_str().to_string()),
        ),
        (
            "os".to_string(),
            AttributeValue::S(event.os.as_str().to_string()),
        ),
        (
            "dv".to_string(),
            AttributeValue::S(event.device.as_str().to_string()),
        ),
        (
            "vi".to_string(),
            AttributeValue::S(event.visitor.as_str().to_string()),
        ),
        (
            "ts".to_string(),
            AttributeValue::N(event.ts_millis.to_string()),
        ),
        (
            "ttl".to_string(),
            AttributeValue::N(event.expires_at.to_string()),
        ),
    ]);

    // Absent rather than empty: a missing attribute costs nothing to store and
    // reads back as `None` without a sentinel value to special-case.
    if let Some(referrer) = &event.referrer {
        item.insert("rf".to_string(), AttributeValue::S(referrer.clone()));
    }
    if let Some(country) = &event.country {
        item.insert("cy".to_string(), AttributeValue::S(country.clone()));
    }

    item
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// The visitor's address, used only to derive the visitor hash.
///
/// Three sources, in descending order of trustworthiness.
///
/// `CloudFront-Viewer-Address` is set by CloudFront from the connection it
/// terminated, and it *overwrites* any value the client sent, so it cannot be
/// forged. That matters: a visitor who can choose the input to the hash can
/// choose their own visitor ID and inflate the unique count at will.
///
/// `X-Forwarded-For` is the fallback, and deliberately only that. Every proxy
/// in the chain appends to it, so with CloudFront in front of API Gateway the
/// viewer address is second from the end rather than last. Depending on a
/// position that shifts when the topology changes is how this breaks quietly,
/// so it is used only when the header above is absent.
fn client_ip(request: &Request) -> String {
    if let Some(address) = header(request, "cloudfront-viewer-address").and_then(strip_port) {
        return address.to_string();
    }

    if let Some(forwarded) = header(request, "x-forwarded-for")
        .and_then(|forwarded| forwarded.split(',').next())
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
    {
        return forwarded.to_string();
    }

    // Nothing in front at all, which is the local-testing case.
    match request.request_context() {
        RequestContext::ApiGatewayV2(context) => context.http.source_ip.unwrap_or_default(),
        _ => String::new(),
    }
}

/// Strip the port from a `CloudFront-Viewer-Address` value.
///
/// The header is `IP:port`, and IPv6 arrives bracketed as `[2001:db8::1]:54321`,
/// so splitting on the last colon is only correct after accounting for the
/// brackets.
fn strip_port(address: &str) -> Option<&str> {
    let address = address.trim();
    if address.is_empty() {
        return None;
    }

    if let Some(bracket) = address.rfind(']') {
        return Some(&address[..=bracket]);
    }

    Some(address.rsplit_once(':').map_or(address, |(ip, _)| ip))
}

fn no_content() -> Response<Body> {
    cors(Response::builder().status(204))
        .body(Body::Empty)
        .expect("valid static response")
}

fn status_only(status: u16) -> Response<Body> {
    cors(Response::builder().status(status))
        .body(Body::Empty)
        .expect("valid static response")
}

fn preflight() -> Response<Body> {
    cors(Response::builder().status(204))
        .header("access-control-allow-methods", "POST, OPTIONS")
        .header("access-control-allow-headers", "content-type")
        .header("access-control-max-age", "86400")
        .body(Body::Empty)
        .expect("valid static response")
}

/// `*` is correct here rather than lax. The endpoint is write-only, returns no
/// body, and is meant to be called from any site that installs the tracker, so
/// there is nothing an origin could learn by being allowed to call it.
fn cors(builder: lambda_http::http::response::Builder) -> lambda_http::http::response::Builder {
    builder
        .header("access-control-allow-origin", "*")
        .header("cache-control", "no-store")
}

#[cfg(test)]
mod tests {
    use super::strip_port;

    #[test]
    fn strips_ipv4_ports() {
        assert_eq!(strip_port("203.0.113.7:54321"), Some("203.0.113.7"));
        assert_eq!(strip_port("203.0.113.7"), Some("203.0.113.7"));
    }

    /// IPv6 arrives bracketed, so splitting on the last colon without checking
    /// for the closing bracket would truncate the address itself.
    #[test]
    fn keeps_ipv6_addresses_intact() {
        assert_eq!(strip_port("[2001:db8::1]:54321"), Some("[2001:db8::1]"));
        assert_eq!(strip_port("[2001:db8::1]"), Some("[2001:db8::1]"));
    }

    #[test]
    fn rejects_empty_values() {
        assert_eq!(strip_port(""), None);
        assert_eq!(strip_port("   "), None);
    }
}
