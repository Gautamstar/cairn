# Cairn

Privacy-first web analytics. One kilobyte of JavaScript, a Rust ingest path on
AWS Lambda, and no way to identify anyone.

A cairn is a small stack of stones travellers leave to mark a path: evidence
that a route was taken, carrying nothing about who took it.

```html
<script defer src="https://<distribution>.cloudfront.net/cairn.js" data-site="portfolio"></script>
```

---

## What it does

Records pageviews, referrers, countries, and device breakdowns for a set of
sites, and serves them on a dashboard. It runs the author's portfolio, Fitmit,
and an EDA web service.

It writes no cookies and touches no browser storage, so a site can install it
without a consent banner. Visitor addresses are never stored: they are hashed
with a key that is regenerated every day, which means the same person is
unrecognisable tomorrow, by construction rather than by policy.

## Architecture

```
browser ──▶ CloudFront ──┬─▶ POST /e             ──▶ cairn-ingest ──▶ DynamoDB
                         ├─▶ GET  /api/stats/:id ──▶ cairn-query  ──▶ DynamoDB
                         └─▶ GET  /*             ──▶ S3 (tracker + dashboard)

              EventBridge (hourly) ──▶ cairn-rollup ──▶ DynamoDB + S3 archive
```

Three Rust binaries on `provided.al2023`, arm64, behind an API Gateway HTTP API.
One DynamoDB table holds raw events and aggregates. Infrastructure is Terraform.

**Ingest does exactly one DynamoDB write.** Bot filtering, user-agent
classification, URL normalisation, and visitor hashing are pure CPU work with no
I/O, so the only network call a visitor waits on is the write itself. Everything
dimensional is derived later.

**The rollup recomputes rather than increments.** Running counters are only
correct if every event is counted exactly once forever, so a cron that fires
twice or a run that dies halfway silently inflates them with no way to audit it
afterwards. Recomputing whole days from raw rows makes the job idempotent: a
failed run needs no cleanup and a bug is fixed by re-running.

**Requests must arrive through CloudFront.** API Gateway is publicly reachable,
so CloudFront attaches a secret header and both handlers refuse requests without
it. Otherwise a direct call arrives without `CloudFront-Viewer-Address` and
visitor identification falls back to a header the caller controls.

## Measured

From CloudWatch on the deployed stack, arm64 at 128 MB:

| | |
|---|---|
| Cold start (init) | 184 ms |
| Warm request with DynamoDB write | 5.1 ms |
| Bot-rejected request | ~1 ms |
| Peak memory | 30 MB of 128 MB |
| Tracker payload | 647 bytes gzipped |

Steady-state cost is $0/month. Lambda, DynamoDB, and CloudFront all sit inside
perpetual free tiers; API Gateway is free for twelve months and roughly a cent a
month after.

## Accounts and sites

Statistics used to be readable by anyone who knew a site id, which was a
deliberate choice while every site belonged to one person. Sites are now owned,
**private by default**, and public only when their owner says so.

```text
POST   /api/auth/signup      {email, password}   sets a session cookie
POST   /api/auth/login       {email, password}
POST   /api/auth/logout
GET    /api/auth/me
GET    /api/sites                                sites you own
POST   /api/sites            {site}              claim one, returns the snippet
PATCH  /api/sites/{site}     {public: bool}       share or unshare
DELETE /api/sites/{site}
```

Sign in at the dashboard, add a site, and paste the snippet it hands back. That
is the whole flow; there is no separate admin surface.

**Passwords, not magic links.** A link would be nicer and would mean storing no
password at all, but it needs SES, a verified domain, and a production-access
request before a single customer can sign up. Argon2 and a cookie need nothing
that is not already deployed. There is no password reset yet, which is
survivable at this size and is the first thing to add if it stops being so.

**Sessions are stored hashed.** The browser gets 32 random bytes as hex; the
table gets a BLAKE3 hash of them under `T#`, with the same `ttl` attribute the
raw events use, so expiry is DynamoDB's job. A dump of the table cannot be
replayed as a login.

**Ingest is untouched.** Adding an ownership lookup to `POST /e` would double
the one DynamoDB round trip the visitor waits on, to reject events that are
already harmless: an unregistered site's rows are unreadable and expire in a
week. Enforcement belongs at read time, and it is there.

**The rollup discovers sites at run time.** Claiming a site adds it to one
string set at `REGISTRY/SITES`, which the rollup reads before each run and
unions with `CAIRN_SITES`. A new customer is aggregated on the next hourly run
without a Terraform apply. Finding `S#` rows any other way would mean scanning a
table that is almost entirely events.

### Upgrading an existing deployment

Three things change behaviour, in the order they bite:

1. **Register your existing sites, or their dashboards go dark.** An
   unregistered site is denied rather than public — defaulting the other way
   would leave every future customer's data readable until they noticed. Sign
   up, then add `portfolio`, `fitmit` and `edaproj`. Mark them public if you
   want them to stay world-readable as they were.
2. **`CAIRN_SITES` is now optional** and acts as a seed list for sites that
   predate the registry. It can stay as it is.
3. **The table moves to on-demand billing.** Provisioned capacity is a fixed
   cost that neither drops on a quiet week nor rises when someone signs up.

The CloudFront changes matter as much as the code: the `cairn_session` cookie is
forwarded to the query handler and included in its cache key, and `/api/auth/*`
and `/api/sites*` get their own behaviours because `/api/*` allows only GET,
HEAD and OPTIONS. Without those, authorization compiles and then denies
everything, and signup returns 403 from the CDN.

## Privacy model

`visitor_id = BLAKE3(daily_salt, site ‖ ip ‖ user_agent)`, truncated, where
`daily_salt` is derived from a secret and the UTC date.

- The address is borrowed for one function call and dropped. `StoredEvent`, the
  only type that reaches the database, **has no field for it**, so persisting one
  would require adding a field and deleting the test that checks for its absence.
- Query strings are stripped before storage, since tokens, session IDs, and
  email addresses live there.
- Fields are length-prefixed before hashing, so `(site: "ab", ip: "c")` and
  `(site: "a", ip: "bc")` cannot collide into one visitor.
- Raw events expire after seven days. Aggregates cannot be un-aggregated.

## Limits

Stated because they follow from the design, not because they are unknown.

**Multi-day visitor counts are sums of daily uniques**, so someone visiting on
two days counts twice. The salt rotates at midnight, so the two IDs are unrelated
values and nothing retained anywhere connects them. A tool reporting true weekly
uniques is necessarily holding an identifier that outlives the day.

**Unique counts use an exact `HashSet`.** Correct and cheap at this scale; it
would need a HyperLogLog sketch somewhere north of a million visitors a day.

**User agents are self-reported.** These are traffic proportions, not identity
claims, and nothing security-relevant is built on them. iPadOS also reports
itself as desktop Safari, which no user-agent parser can detect.

## Layout

```
crates/core      domain logic: events, hashing, bot filter, UA, normalisation
crates/account   accounts, sessions, site ownership
crates/ingest    POST /e
crates/query     GET /api/stats/:site
crates/rollup    scheduled aggregation
tracker/         the browser script
web/             the dashboard
infra/           Terraform
```

`cairn-core` has no AWS dependency and does no I/O: the clock, the address, and
the secret are all passed in, which is what keeps it testable with `cargo test`.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Deployment, including the one secret Terraform deliberately does not manage, is
in [`infra/README.md`](infra/README.md).

## License

MIT
