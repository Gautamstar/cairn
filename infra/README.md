# Deploying Cairn

## The secret is not managed by Terraform, on purpose

Cairn's visitor hashing depends on one long-lived secret, stored as an SSM
SecureString. Terraform grants access to it by name and never touches its value.

That is deliberate. If Terraform created the parameter, the plaintext secret
would be written into `terraform.tfstate`, which is an unencrypted JSON file on
disk. State is gitignored, but "the secret is safe because a gitignore entry is
correct" is a worse guarantee than "the secret is never written there at all".
And the visitor IDs are only irreversible while the secret holds: with it, the
entire IPv4 space can be brute-forced against a day's hashes in minutes.

So it gets created once, by hand:

```powershell
$bytes = New-Object byte[] 32
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$rng.GetBytes($bytes); $rng.Dispose()

# Refuse to store the result unless randomness actually happened.
$nonzero = ($bytes | Where-Object { $_ -ne 0 }).Count
if ($nonzero -lt 25) { throw "entropy check failed" }

aws ssm put-parameter --name /cairn/visitor-salt --type SecureString --value ([Convert]::ToBase64String($bytes)) --region us-east-2
```

Three details here are load-bearing, and each one has a silent failure mode.

`RNGCryptoServiceProvider`, not `Get-Random`, which is not cryptographically
secure and would leave the salt guessable.

`RNGCryptoServiceProvider`, not `RandomNumberGenerator::Fill`, which reads like
the modern replacement and is: it exists in .NET Core 3.0 and later, but not in
the .NET Framework that Windows PowerShell 5.1 runs on. Calling it there throws
a `MethodNotFound` *after* `$bytes` has already been allocated as 32 zeros, so
the pipeline carries on and stores a base64 string of zeros as the secret. It
looks like a perfectly normal secret and is completely predictable.

Hence the entropy check. It costs one line and turns that class of failure from
silent into loud.

**Do not rotate this casually.** Changing it changes every visitor ID
immediately, so rotating mid-day makes returning visitors look new and inflates
that day's unique count. If it must be rotated, do it at a UTC midnight.

## First deploy

```powershell
aws sts get-caller-identity
```

Confirm the ARN ends in an IAM user, not `:root`.

**1. Build the Lambdas.** Terraform reads the zips at plan time, so this comes
first or `terraform plan` fails on a missing file.

```powershell
cargo lambda build --release --arm64 --output-format zip
```

**2. Apply.**

```powershell
terraform -chdir=infra init
```

```powershell
terraform -chdir=infra plan
```

Read the plan. It should create around 37 resources and destroy none.

```powershell
terraform -chdir=infra apply
```

The CloudFront distribution takes several minutes to reach every edge. The
apply returns before propagation finishes, so a 403 in the first few minutes is
expected rather than broken.

**3. Upload the tracker.**

```powershell
aws s3 cp tracker/cairn.js "s3://$(terraform -chdir=infra output -raw assets_bucket)/cairn.js" --content-type application/javascript --cache-control "public, max-age=3600"
```

## Smoke test

```powershell
curl -i -X POST "$(terraform -chdir=infra output -raw ingest_endpoint)" -H "Content-Type: text/plain" -d '{\"site\":\"gautamstar.github.io\",\"url\":\"https://gautamstar.github.io/portfolio/\"}'
```

Expect `204 No Content`. Then confirm the row landed, substituting the current
UTC hour:

```powershell
aws dynamodb query --table-name cairn --key-condition-expression "pk = :pk" --expression-attribute-values '{\":pk\":{\"S\":\"E#gautamstar.github.io#2026-08-02T14\"}}' --region us-east-2
```

Two things to verify by eye, because they are the claims the project makes:

- the item has **no attribute containing an IP address**
- the same is true in CloudWatch Logs for `/aws/lambda/cairn-ingest`

A `curl` user agent is caught by the bot filter, so the smoke test above will
return 204 without writing anything. Add `-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0.0.0"`
to get a row.

## Teardown

```powershell
terraform -chdir=infra destroy
```

Buckets must be emptied first, since Terraform will not delete a bucket with
objects in it. The SSM parameter survives, because Terraform never owned it.

## Cost

Every load-bearing service here sits on a perpetual free tier: Lambda (1M
requests, 400k GB-seconds), DynamoDB (25 RCU/WCU, 25 GB), CloudFront (1 TB, 10M
requests), Function URLs (no per-request charge), SSM Parameter Store Standard.
S3's 5 GB is the only 12-month allowance, and the archive is measured in
megabytes.

Expected steady state is $0. The $1 budget alert is what turns that expectation
into something you find out about rather than discover on a statement.
