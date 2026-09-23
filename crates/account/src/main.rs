//! Accounts and site ownership: signup, login, and which sites a person owns.
//!
//! Split from `cairn-query` on purpose. Query is the hot read path the
//! dashboard polls; this handler runs rarely, does the deliberately slow
//! Argon2 work, and holds the only write access to account rows. Keeping them
//! apart means a password hash never costs a stats request any latency.
//!
//! ## Routes
//!
//! ```text
//! POST   /api/auth/signup      {email, password}  -> sets session cookie
//! POST   /api/auth/login       {email, password}  -> sets session cookie
//! POST   /api/auth/logout                         -> clears it
//! GET    /api/auth/me                             -> who am I
//! GET    /api/sites                               -> sites I own
//! POST   /api/sites            {site}             -> claim one
//! PATCH  /api/sites/{site}     {public: bool}     -> share or unshare
//! DELETE /api/sites/{site}                        -> give it up
//! ```

use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use cairn_core::account::{self, AccountError, Email, SESSION_DAYS, SessionToken, SiteId};
use lambda_http::{Body, Error, Request, Response, run, service_fn};
use rand::RngCore;
use serde::Deserialize;
use time::OffsetDateTime;

/// Name of the cookie carrying the session token.
const COOKIE: &str = "cairn_session";

struct App {
    dynamo: aws_sdk_dynamodb::Client,
    table: String,
    origin_secret: Option<String>,
    /// Set false only for local testing over plain HTTP; the cookie is
    /// otherwise marked `Secure` and a browser will refuse to send it.
    secure_cookies: bool,
}

impl App {
    async fn init() -> Result<Self, Error> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let table = std::env::var("CAIRN_TABLE")
            .map_err(|_| "CAIRN_TABLE must be set to the DynamoDB table name")?;
        Ok(Self {
            dynamo: aws_sdk_dynamodb::Client::new(&config),
            table,
            origin_secret: std::env::var("CAIRN_ORIGIN_SECRET")
                .ok()
                .filter(|secret| !secret.is_empty()),
            secure_cookies: std::env::var("CAIRN_INSECURE_COOKIES").is_err(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct Credentials {
    email: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct SiteRequest {
    site: String,
}

#[derive(Debug, Deserialize)]
struct VisibilityRequest {
    public: bool,
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
    if let Some(expected) = &app.origin_secret {
        let presented = request
            .headers()
            .get(cairn_core::ORIGIN_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !cairn_core::secret_matches(expected, presented) {
            return Ok(error(403, "forbidden"));
        }
    }

    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();

    let result = match (method.as_str(), path.as_str()) {
        ("POST", "/api/auth/signup") => signup(&app, &request).await,
        ("POST", "/api/auth/login") => login(&app, &request).await,
        ("POST", "/api/auth/logout") => Ok(logout(&app)),
        ("GET", "/api/auth/me") => me(&app, &request).await,
        ("GET", "/api/sites") => list_sites(&app, &request).await,
        ("POST", "/api/sites") => claim_site(&app, &request).await,
        ("PATCH", p) if p.starts_with("/api/sites/") => set_visibility(&app, &request, p).await,
        ("DELETE", p) if p.starts_with("/api/sites/") => release_site(&app, &request, p).await,
        _ => Ok(error(404, "no such route")),
    };

    // A handler that fails against DynamoDB should not hand the caller a stack
    // trace, but it must still show up in CloudWatch as an error.
    Ok(result.unwrap_or_else(|err| {
        tracing::error!(error = %err, method, path, "account handler failed");
        error(500, "internal error")
    }))
}

/* ----------------------------------------------------------------------- */
/* auth                                                                     */
/* ----------------------------------------------------------------------- */

async fn signup(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(creds) = body::<Credentials>(request) else {
        return Ok(error(400, "expected {email, password}"));
    };
    let email = match Email::parse(&creds.email) {
        Ok(email) => email,
        Err(err) => return Ok(error(400, &err.to_string())),
    };

    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let hash = match account::hash_password(&creds.password, &salt) {
        Ok(hash) => hash,
        Err(AccountError::PasswordTooShort) => {
            return Ok(error(400, &AccountError::PasswordTooShort.to_string()));
        }
        Err(err) => return Ok(error(400, &err.to_string())),
    };

    let created = OffsetDateTime::now_utc().unix_timestamp();
    let put = app
        .dynamo
        .put_item()
        .table_name(&app.table)
        .item("pk", AttributeValue::S(email.pk()))
        .item("sk", AttributeValue::S("PROFILE".into()))
        .item("password_hash", AttributeValue::S(hash))
        .item("plan", AttributeValue::S("free".into()))
        .item("created_at", AttributeValue::N(created.to_string()))
        // Atomic: two simultaneous signups for one address, one wins.
        .condition_expression("attribute_not_exists(pk)")
        .send()
        .await;

    if let Err(err) = put {
        if conditional_failure(&err) {
            return Ok(error(409, "that email already has an account"));
        }
        return Err(err.into());
    }

    let token = issue_session(app, &email).await?;
    Ok(with_session_cookie(
        app,
        json(200, &serde_json::json!({ "email": email.as_str() })),
        &token,
    ))
}

async fn login(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(creds) = body::<Credentials>(request) else {
        return Ok(error(400, "expected {email, password}"));
    };
    let Ok(email) = Email::parse(&creds.email) else {
        // Same answer as a wrong password: a malformed address must not be
        // distinguishable from an unregistered one.
        return Ok(error(401, "email or password is wrong"));
    };

    let profile = app
        .dynamo
        .get_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(email.pk()))
        .key("sk", AttributeValue::S("PROFILE".into()))
        .send()
        .await?;

    let stored = profile
        .item()
        .and_then(|item| item.get("password_hash"))
        .and_then(|value| value.as_s().ok())
        .cloned()
        .unwrap_or_default();

    // Verify even when the account is missing, so a request for an unknown
    // address takes the same visible time as one for a known address.
    if !account::verify_password(&creds.password, &stored) {
        return Ok(error(401, "email or password is wrong"));
    }

    let token = issue_session(app, &email).await?;
    Ok(with_session_cookie(
        app,
        json(200, &serde_json::json!({ "email": email.as_str() })),
        &token,
    ))
}

fn logout(app: &App) -> Response<Body> {
    // The row is left to its TTL. Clearing the cookie is what ends the session
    // for this browser, and a deletion here would be one more write on a path
    // that does not need to be durable.
    let cleared = format!(
        "{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if app.secure_cookies { "; Secure" } else { "" }
    );
    let mut response = json(200, &serde_json::json!({ "ok": true }));
    response
        .headers_mut()
        .insert("set-cookie", cleared.parse().expect("valid cookie"));
    response
}

async fn me(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    match session_email(app, request).await? {
        Some(email) => Ok(json(200, &serde_json::json!({ "email": email.as_str() }))),
        None => Ok(error(401, "not signed in")),
    }
}

/// Write a session row and return the token to hand to the browser.
async fn issue_session(app: &App, email: &Email) -> Result<SessionToken, Error> {
    let mut entropy = [0u8; 32];
    rand::rng().fill_bytes(&mut entropy);
    let token = SessionToken::from_entropy(&entropy);
    let expires = OffsetDateTime::now_utc().unix_timestamp() + SESSION_DAYS * 86_400;

    app.dynamo
        .put_item()
        .table_name(&app.table)
        .item("pk", AttributeValue::S(SessionToken::pk(token.hash())))
        .item("sk", AttributeValue::S("SESSION".into()))
        .item("email", AttributeValue::S(email.as_str().to_string()))
        // Same `ttl` attribute the raw events use, so DynamoDB reaps expired
        // sessions without a sweeper of our own.
        .item("ttl", AttributeValue::N(expires.to_string()))
        .send()
        .await?;

    Ok(token)
}

/// The signed-in account, or `None`. Reads the cookie, never a query string.
async fn session_email(app: &App, request: &Request) -> Result<Option<Email>, Error> {
    let Some(presented) = cookie_value(request, COOKIE) else {
        return Ok(None);
    };
    let hash = SessionToken::hash_presented(&presented);

    let found = app
        .dynamo
        .get_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(SessionToken::pk(&hash)))
        .key("sk", AttributeValue::S("SESSION".into()))
        .send()
        .await?;

    let Some(item) = found.item() else {
        return Ok(None);
    };

    // DynamoDB's TTL deletes within 48 hours of expiry rather than at it, so
    // the timestamp is checked here too instead of trusting the row's presence.
    let expired = item
        .get("ttl")
        .and_then(|value| value.as_n().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .is_none_or(|expires| expires <= OffsetDateTime::now_utc().unix_timestamp());
    if expired {
        return Ok(None);
    }

    Ok(item
        .get("email")
        .and_then(|value| value.as_s().ok())
        .and_then(|email| Email::parse(email).ok()))
}

/* ----------------------------------------------------------------------- */
/* sites                                                                    */
/* ----------------------------------------------------------------------- */

async fn list_sites(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(email) = session_email(app, request).await? else {
        return Ok(error(401, "not signed in"));
    };

    let rows = app
        .dynamo
        .query()
        .table_name(&app.table)
        .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
        .expression_attribute_values(":pk", AttributeValue::S(email.pk()))
        .expression_attribute_values(":prefix", AttributeValue::S("SITE#".into()))
        .send()
        .await?;

    let sites: Vec<_> = rows
        .items()
        .iter()
        .filter_map(|item| {
            let site = item.get("site")?.as_s().ok()?;
            let public = item
                .get("public")
                .and_then(|value| value.as_bool().ok())
                .copied()
                .unwrap_or(false);
            Some(serde_json::json!({
                "site": site,
                "public": public,
                "added_at": item.get("added_at").and_then(|v| v.as_n().ok()).cloned(),
            }))
        })
        .collect();

    Ok(json(200, &serde_json::json!({ "sites": sites })))
}

async fn claim_site(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(email) = session_email(app, request).await? else {
        return Ok(error(401, "not signed in"));
    };
    let Some(payload) = body::<SiteRequest>(request) else {
        return Ok(error(400, "expected {site}"));
    };
    let site = match SiteId::parse(&payload.site) {
        Ok(site) => site,
        Err(err) => return Ok(error(400, &err.to_string())),
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();

    // The ownership row is the claim. A conditional put makes "first to
    // register wins" atomic without a transaction.
    let claim = app
        .dynamo
        .put_item()
        .table_name(&app.table)
        .item("pk", AttributeValue::S(site.pk()))
        .item("sk", AttributeValue::S("META".into()))
        .item("site", AttributeValue::S(site.as_str().to_string()))
        .item("owner", AttributeValue::S(email.as_str().to_string()))
        .item("public", AttributeValue::Bool(false))
        .item("created_at", AttributeValue::N(now.to_string()))
        .condition_expression("attribute_not_exists(pk)")
        .send()
        .await;

    if let Err(err) = claim {
        if conditional_failure(&err) {
            return Ok(error(409, "that site id is already registered"));
        }
        return Err(err.into());
    }

    // Membership row, so listing a user's sites is one query on their own
    // partition rather than a table scan.
    app.dynamo
        .put_item()
        .table_name(&app.table)
        .item("pk", AttributeValue::S(email.pk()))
        .item("sk", AttributeValue::S(site.membership_sk()))
        .item("site", AttributeValue::S(site.as_str().to_string()))
        .item("public", AttributeValue::Bool(false))
        .item("added_at", AttributeValue::N(now.to_string()))
        .send()
        .await?;

    // The rollup reads this set to know what to aggregate. A site missing from
    // it collects events that never become a dashboard.
    app.dynamo
        .update_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(account::REGISTRY_PK.into()))
        .key("sk", AttributeValue::S(account::REGISTRY_SK.into()))
        .update_expression("ADD #sites :site")
        .expression_attribute_names("#sites", "sites")
        .expression_attribute_values(":site", AttributeValue::Ss(vec![site.as_str().to_string()]))
        .send()
        .await?;

    Ok(json(
        201,
        &serde_json::json!({
            "site": site.as_str(),
            "public": false,
            "snippet": snippet(site.as_str()),
        }),
    ))
}

async fn set_visibility(app: &App, request: &Request, path: &str) -> Result<Response<Body>, Error> {
    let Some(email) = session_email(app, request).await? else {
        return Ok(error(401, "not signed in"));
    };
    let Some(site) = site_from_path(path) else {
        return Ok(error(400, "bad site id"));
    };
    let Some(payload) = body::<VisibilityRequest>(request) else {
        return Ok(error(400, "expected {public}"));
    };
    if !owns(app, &email, &site).await? {
        // Not 403: a stranger should not learn that this site exists.
        return Ok(error(404, "no such site"));
    }

    for (pk, sk) in [
        (site.pk(), "META".to_string()),
        (email.pk(), site.membership_sk()),
    ] {
        app.dynamo
            .update_item()
            .table_name(&app.table)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(sk))
            .update_expression("SET #public = :public")
            .expression_attribute_names("#public", "public")
            .expression_attribute_values(":public", AttributeValue::Bool(payload.public))
            .send()
            .await?;
    }

    Ok(json(
        200,
        &serde_json::json!({ "site": site.as_str(), "public": payload.public }),
    ))
}

async fn release_site(app: &App, request: &Request, path: &str) -> Result<Response<Body>, Error> {
    let Some(email) = session_email(app, request).await? else {
        return Ok(error(401, "not signed in"));
    };
    let Some(site) = site_from_path(path) else {
        return Ok(error(400, "bad site id"));
    };
    if !owns(app, &email, &site).await? {
        return Ok(error(404, "no such site"));
    }

    for (pk, sk) in [
        (site.pk(), "META".to_string()),
        (email.pk(), site.membership_sk()),
    ] {
        app.dynamo
            .delete_item()
            .table_name(&app.table)
            .key("pk", AttributeValue::S(pk))
            .key("sk", AttributeValue::S(sk))
            .send()
            .await?;
    }

    app.dynamo
        .update_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(account::REGISTRY_PK.into()))
        .key("sk", AttributeValue::S(account::REGISTRY_SK.into()))
        .update_expression("DELETE #sites :site")
        .expression_attribute_names("#sites", "sites")
        .expression_attribute_values(":site", AttributeValue::Ss(vec![site.as_str().to_string()]))
        .send()
        .await?;

    // Events already collected are left alone; they carry no owner and expire
    // on their own TTL. Releasing a site frees the id, it does not erase history.
    Ok(json(200, &serde_json::json!({ "released": site.as_str() })))
}

async fn owns(app: &App, email: &Email, site: &SiteId) -> Result<bool, Error> {
    let found = app
        .dynamo
        .get_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(site.pk()))
        .key("sk", AttributeValue::S("META".into()))
        .send()
        .await?;

    Ok(found
        .item()
        .and_then(|item| item.get("owner"))
        .and_then(|value| value.as_s().ok())
        .is_some_and(|owner| owner == email.as_str()))
}

fn snippet(site: &str) -> String {
    format!(r#"<script defer src="/cairn.js" data-site="{site}"></script>"#)
}

/* ----------------------------------------------------------------------- */
/* plumbing                                                                 */
/* ----------------------------------------------------------------------- */

/// The site is the final path segment of `/api/sites/{site}`.
fn site_from_path(path: &str) -> Option<SiteId> {
    let raw = path.rsplit('/').find(|segment| !segment.is_empty())?;
    if raw == "sites" {
        return None;
    }
    SiteId::parse(raw).ok()
}

fn body<T: for<'de> Deserialize<'de>>(request: &Request) -> Option<T> {
    serde_json::from_slice(request.body().as_ref()).ok()
}

fn cookie_value(request: &Request, name: &str) -> Option<String> {
    let header = request.headers().get("cookie")?.to_str().ok()?;
    account::cookie_value(header, name).map(str::to_owned)
}

fn with_session_cookie(
    app: &App,
    mut response: Response<Body>,
    token: &SessionToken,
) -> Response<Body> {
    // HttpOnly so a cross-site script cannot read it; SameSite=Lax so it is
    // not sent on a cross-site POST; Secure everywhere but local testing.
    let cookie = format!(
        "{COOKIE}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        token.plaintext(),
        SESSION_DAYS * 86_400,
        if app.secure_cookies { "; Secure" } else { "" }
    );
    response
        .headers_mut()
        .insert("set-cookie", cookie.parse().expect("valid cookie"));
    response
}

/// Did a conditional put lose the race, as opposed to failing for real?
///
/// Typed rather than matched on the error's text: "already exists" and "the
/// database is down" must not be one branch.
fn conditional_failure<R>(err: &aws_sdk_dynamodb::error::SdkError<PutItemError, R>) -> bool {
    err.as_service_error()
        .is_some_and(PutItemError::is_conditional_check_failed_exception)
}

fn json(status: u16, value: &serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        // Account responses are per-session and must never be cached by
        // CloudFront or a browser.
        .header("cache-control", "no-store")
        .body(Body::from(value.to_string()))
        .expect("valid static response")
}

fn error(status: u16, message: &str) -> Response<Body> {
    json(status, &serde_json::json!({ "error": message }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_is_read_from_the_last_path_segment() {
        assert_eq!(
            site_from_path("/api/sites/fitmit").map(|s| s.as_str().to_string()),
            Some("fitmit".to_string())
        );
        assert_eq!(
            site_from_path("/api/sites/fitmit/").map(|s| s.as_str().to_string()),
            Some("fitmit".to_string())
        );
        assert!(site_from_path("/api/sites").is_none());
        assert!(site_from_path("/api/sites/not a site").is_none());
    }

    #[test]
    fn the_snippet_names_the_site() {
        assert!(snippet("fitmit").contains(r#"data-site="fitmit""#));
    }
}
