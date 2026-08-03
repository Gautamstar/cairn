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
