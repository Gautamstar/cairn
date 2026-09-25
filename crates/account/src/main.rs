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
//! GET    /api/billing/summary                     -> plan, limits, usage
//! POST   /api/billing/checkout {plan}             -> a Payment Link to pay
//! POST   /api/billing/webhook                     -> Stripe, signed
//! ```

use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::operation::put_item::PutItemError;
use aws_sdk_dynamodb::types::AttributeValue;
use cairn_core::account::{self, AccountError, Email, Plan, SESSION_DAYS, SessionToken, SiteId};
use cairn_core::billing::{self, BillingEvent};
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
    /// `None` until Stripe is configured. The product works without it: every
    /// account is simply on the free plan and the upgrade routes say so.
    billing: Option<Billing>,
}

/// Stripe configuration. Two Payment Links, one per paid plan, and the secret
/// that signs webhooks. No Stripe API key: nothing here calls Stripe.
struct Billing {
    webhook_secret: String,
    starter_url: String,
    starter_link_id: String,
    pro_url: String,
    pro_link_id: String,
    /// Stripe's hosted Customer Portal login link, where a paying customer
    /// cancels or updates their card. Optional; without it they email you.
    portal_url: Option<String>,
}

impl Billing {
    fn from_env() -> Option<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        Some(Self {
            webhook_secret: var("CAIRN_STRIPE_WEBHOOK_SECRET")?,
            starter_url: var("CAIRN_STRIPE_STARTER_URL")?,
            starter_link_id: var("CAIRN_STRIPE_STARTER_LINK_ID")?,
            pro_url: var("CAIRN_STRIPE_PRO_URL")?,
            pro_link_id: var("CAIRN_STRIPE_PRO_LINK_ID")?,
            portal_url: var("CAIRN_STRIPE_PORTAL_URL"),
        })
    }
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
            billing: Billing::from_env(),
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
        ("GET", "/api/billing/summary") => account_summary(&app, &request).await,
        ("POST", "/api/billing/checkout") => checkout(&app, &request).await,
        ("POST", "/api/billing/webhook") => webhook(&app, &request).await,
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
    let sites: Vec<_> = owned_sites(app, &email)
        .await?
        .into_iter()
        .map(|owned| serde_json::json!({ "site": owned.site, "public": owned.public }))
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

    // Checked before the claim, so a refused site id stays free for whoever
    // asks next. Not transactional: two simultaneous claims at the limit can
    // both pass. At worst that is one site over, on the account's own quota,
    // which is not worth a transaction on every claim.
    let plan = load_plan(app, &email).await?;
    let owned = owned_sites(app, &email).await?.len();
    if owned >= plan.max_sites() {
        return Ok(error(
            402,
            &format!(
                "the {} plan includes {} site{}; upgrade to add another",
                plan.as_str(),
                plan.max_sites(),
                if plan.max_sites() == 1 { "" } else { "s" }
            ),
        ));
    }

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

/* ----------------------------------------------------------------------- */
/* plans, usage, billing                                                    */
/* ----------------------------------------------------------------------- */

struct OwnedSite {
    site: String,
    public: bool,
}

/// The sites an account owns, from its membership rows.
async fn owned_sites(app: &App, email: &Email) -> Result<Vec<OwnedSite>, Error> {
    let rows = app
        .dynamo
        .query()
        .table_name(&app.table)
        .key_condition_expression("pk = :pk AND begins_with(sk, :prefix)")
        .expression_attribute_values(":pk", AttributeValue::S(email.pk()))
        .expression_attribute_values(":prefix", AttributeValue::S("SITE#".into()))
        .send()
        .await?;

    Ok(rows
        .items()
        .iter()
        .filter_map(|item| {
            Some(OwnedSite {
                site: item.get("site")?.as_s().ok()?.clone(),
                public: item
                    .get("public")
                    .and_then(|value| value.as_bool().ok())
                    .copied()
                    .unwrap_or(false),
            })
        })
        .collect())
}

async fn load_profile(
    app: &App,
    email: &Email,
) -> Result<Option<std::collections::HashMap<String, AttributeValue>>, Error> {
    let found = app
        .dynamo
        .get_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(email.pk()))
        .key("sk", AttributeValue::S("PROFILE".into()))
        .send()
        .await?;
    Ok(found.item().cloned())
}

async fn load_plan(app: &App, email: &Email) -> Result<Plan, Error> {
    Ok(load_profile(app, email)
        .await?
        .and_then(|item| item.get("plan").and_then(|v| v.as_s().ok()).cloned())
        .map(|name| Plan::parse(&name))
        .unwrap_or(Plan::Free))
}

/// Events recorded for one site in one `YYYY-MM`, summed from the per-day
/// usage rows the rollup overwrites.
async fn month_usage(app: &App, site: &str, month: &str) -> Result<u64, Error> {
    let rows = app
        .dynamo
        .query()
        .table_name(&app.table)
        .key_condition_expression("pk = :pk AND begins_with(sk, :month)")
        .expression_attribute_values(":pk", AttributeValue::S(account::usage_pk(site)))
        .expression_attribute_values(":month", AttributeValue::S(month.to_string()))
        .send()
        .await?;

    Ok(rows
        .items()
        .iter()
        .filter_map(|item| item.get("events")?.as_n().ok()?.parse::<u64>().ok())
        .sum())
}

fn plan_json(plan: Plan) -> serde_json::Value {
    serde_json::json!({
        "name": plan.as_str(),
        "max_sites": plan.max_sites(),
        "monthly_events": plan.monthly_events(),
        "retention_days": plan.retention_days(),
        "price": plan.monthly_price(),
    })
}

/// Plan, limits and this month's usage, for the dashboard.
///
/// Going over the event allowance is reported, not enforced. Events keep
/// being collected and shown; cutting a paying site's dashboard off mid-month
/// is a decision to make with real customers, not a default to ship.
async fn account_summary(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(email) = session_email(app, request).await? else {
        return Ok(error(401, "not signed in"));
    };

    let plan = load_plan(app, &email).await?;
    let month = OffsetDateTime::now_utc().date().to_string();
    let month = account::usage_month_prefix(&month).to_string();

    let mut per_site = Vec::new();
    let mut total = 0u64;
    let sites = owned_sites(app, &email).await?;
    for owned in &sites {
        let events = month_usage(app, &owned.site, &month).await?;
        total += events;
        per_site.push(serde_json::json!({ "site": owned.site, "events": events }));
    }

    Ok(json(
        200,
        &serde_json::json!({
            "email": email.as_str(),
            "plan": plan_json(plan),
            "usage": {
                "month": month,
                "events": total,
                "sites": per_site,
                "site_count": sites.len(),
                "over_events": total > plan.monthly_events(),
                "over_sites": sites.len() > plan.max_sites(),
            },
            "billing_available": app.billing.is_some(),
            // Only a free account is offered Payment Links. A second Payment
            // Link on a paying account starts a second subscription beside
            // the first, and the customer is charged for both.
            "plans": if plan == Plan::Free {
                vec![plan_json(Plan::Starter), plan_json(Plan::Pro)]
            } else {
                Vec::new()
            },
            "portal_url": app
                .billing
                .as_ref()
                .filter(|_| plan != Plan::Free)
                .and_then(|billing| billing.portal_url.clone()),
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct CheckoutRequest {
    plan: String,
}

/// A Payment Link for the signed-in account, carrying its billing reference.
async fn checkout(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(billing) = &app.billing else {
        return Ok(error(503, "billing is not set up on this deployment"));
    };
    let Some(email) = session_email(app, request).await? else {
        return Ok(error(401, "not signed in"));
    };
    let Some(payload) = body::<CheckoutRequest>(request) else {
        return Ok(error(400, "expected {plan}"));
    };
    let link = match Plan::parse(&payload.plan) {
        Plan::Starter => &billing.starter_url,
        Plan::Pro => &billing.pro_url,
        Plan::Free => return Ok(error(400, "choose starter or pro")),
    };
    // Enforced here as well as hidden in the dashboard, since the route can be
    // called directly: a paying account buying again means two subscriptions.
    if load_plan(app, &email).await? != Plan::Free {
        return Ok(error(
            409,
            "this account already has a paid plan; change or cancel it under Manage billing",
        ));
    }

    let reference = ensure_billing_ref(app, &email).await?;
    let url = format!(
        "{link}?client_reference_id={reference}&prefilled_email={}",
        percent_encode(email.as_str())
    );
    Ok(json(200, &serde_json::json!({ "url": url })))
}

/// The account's billing reference, issuing one on first use.
async fn ensure_billing_ref(app: &App, email: &Email) -> Result<String, Error> {
    if let Some(existing) = load_profile(app, email)
        .await?
        .and_then(|item| item.get("billing_ref").and_then(|v| v.as_s().ok()).cloned())
    {
        return Ok(existing);
    }

    let mut entropy = [0u8; 16];
    rand::rng().fill_bytes(&mut entropy);
    let fresh = billing::billing_ref(&entropy);

    // Conditional, so two tabs clicking Upgrade at once agree on one reference
    // instead of each writing their own and orphaning the other's payment.
    let set = app
        .dynamo
        .update_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(email.pk()))
        .key("sk", AttributeValue::S("PROFILE".into()))
        .update_expression("SET billing_ref = :r")
        .condition_expression("attribute_exists(pk) AND attribute_not_exists(billing_ref)")
        .expression_attribute_values(":r", AttributeValue::S(fresh.clone()))
        .send()
        .await;

    let reference = match set {
        Ok(_) => fresh,
        Err(err) => {
            let lost_race = err
                .as_service_error()
                .is_some_and(|e| e.is_conditional_check_failed_exception());
            if !lost_race {
                return Err(err.into());
            }
            load_profile(app, email)
                .await?
                .and_then(|item| item.get("billing_ref").and_then(|v| v.as_s().ok()).cloned())
                .ok_or("billing reference vanished after a lost race")?
        }
    };

    // Reverse lookup, so the webhook can find the account from the reference.
    app.dynamo
        .put_item()
        .table_name(&app.table)
        .item("pk", AttributeValue::S(billing::billing_ref_pk(&reference)))
        .item("sk", AttributeValue::S("ACCOUNT".into()))
        .item("email", AttributeValue::S(email.as_str().to_string()))
        .send()
        .await?;

    Ok(reference)
}

/// Stripe's webhook. Unauthenticated by session: authenticated by signature.
///
/// Anything this handler cannot act on still gets a 200. A non-2xx makes
/// Stripe retry for three days, and retrying an event that names an unknown
/// account will never start succeeding. Those cases are logged as errors
/// instead, where they will be seen.
async fn webhook(app: &App, request: &Request) -> Result<Response<Body>, Error> {
    let Some(config) = &app.billing else {
        return Ok(error(503, "billing is not set up on this deployment"));
    };

    let signature = request
        .headers()
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let raw = request.body().as_ref();
    let now = OffsetDateTime::now_utc().unix_timestamp();

    if !billing::verify_signature(signature, raw, &config.webhook_secret, now) {
        tracing::warn!("webhook with a bad or stale signature");
        return Ok(error(400, "bad signature"));
    }
    let Some(event) = BillingEvent::parse(raw) else {
        return Ok(error(400, "not a stripe event"));
    };

    match event {
        BillingEvent::CheckoutCompleted {
            reference,
            payment_link,
            subscription,
            customer,
        } => {
            let Some(plan) =
                billing::plan_for_link(&payment_link, &config.starter_link_id, &config.pro_link_id)
            else {
                tracing::error!(
                    payment_link,
                    "paid checkout for a payment link that is not configured"
                );
                return Ok(ok());
            };
            if !billing::is_billing_ref(&reference) {
                tracing::error!(
                    reference,
                    "paid checkout with a malformed billing reference"
                );
                return Ok(ok());
            }
            let Some(email) = lookup_email(app, &billing::billing_ref_pk(&reference)).await? else {
                tracing::error!(reference, "paid checkout for an unknown billing reference");
                return Ok(ok());
            };

            app.dynamo
                .update_item()
                .table_name(&app.table)
                .key("pk", AttributeValue::S(email.pk()))
                .key("sk", AttributeValue::S("PROFILE".into()))
                .update_expression(
                    "SET #plan = :plan, stripe_customer = :c, stripe_subscription = :s",
                )
                .expression_attribute_names("#plan", "plan")
                .expression_attribute_values(":plan", AttributeValue::S(plan.as_str().into()))
                .expression_attribute_values(":c", AttributeValue::S(customer))
                .expression_attribute_values(":s", AttributeValue::S(subscription.clone()))
                .send()
                .await?;

            app.dynamo
                .put_item()
                .table_name(&app.table)
                .item(
                    "pk",
                    AttributeValue::S(billing::subscription_pk(&subscription)),
                )
                .item("sk", AttributeValue::S("ACCOUNT".into()))
                .item("email", AttributeValue::S(email.as_str().to_string()))
                .send()
                .await?;

            tracing::info!(plan = plan.as_str(), "plan granted");
        }

        BillingEvent::SubscriptionEnded { subscription } => {
            let Some(email) = lookup_email(app, &billing::subscription_pk(&subscription)).await?
            else {
                return Ok(ok());
            };

            // Only the subscription the account is currently on may downgrade
            // it. Someone who upgraded to Pro and then cancelled their old
            // Starter must not be dropped to free by the Starter's ending.
            let downgrade = app
                .dynamo
                .update_item()
                .table_name(&app.table)
                .key("pk", AttributeValue::S(email.pk()))
                .key("sk", AttributeValue::S("PROFILE".into()))
                .update_expression("SET #plan = :free REMOVE stripe_subscription")
                .condition_expression("stripe_subscription = :sub")
                .expression_attribute_names("#plan", "plan")
                .expression_attribute_values(":free", AttributeValue::S(Plan::Free.as_str().into()))
                .expression_attribute_values(":sub", AttributeValue::S(subscription))
                .send()
                .await;

            match downgrade {
                Ok(_) => tracing::info!("plan ended, back to free"),
                Err(err)
                    if err
                        .as_service_error()
                        .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
                {
                    tracing::info!("ended subscription was not the current one; plan unchanged");
                }
                Err(err) => return Err(err.into()),
            }
        }

        BillingEvent::Ignored => {}
    }

    Ok(ok())
}

async fn lookup_email(app: &App, pk: &str) -> Result<Option<Email>, Error> {
    let found = app
        .dynamo
        .get_item()
        .table_name(&app.table)
        .key("pk", AttributeValue::S(pk.to_string()))
        .key("sk", AttributeValue::S("ACCOUNT".into()))
        .send()
        .await?;
    Ok(found
        .item()
        .and_then(|item| item.get("email"))
        .and_then(|v| v.as_s().ok())
        .and_then(|raw| Email::parse(raw).ok()))
}

fn ok() -> Response<Body> {
    json(200, &serde_json::json!({ "received": true }))
}

/// Percent-encode a query value. Only what an email address can contain needs
/// handling, but everything outside the unreserved set is encoded regardless.
fn percent_encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
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
    fn an_email_survives_a_query_string() {
        assert_eq!(percent_encode("a.b+c@example.com"), "a.b%2Bc%40example.com");
        assert_eq!(percent_encode("plain"), "plain");
    }
}
