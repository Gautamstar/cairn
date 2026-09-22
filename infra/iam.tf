data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# One role per function rather than one shared role. The point is visible in the
# policies below: ingest can write events but cannot read a single one back, and
# query can read but cannot write. A shared role would hand every function the
# union of all three, and the blast radius of a bug in the public write endpoint
# would become "everything Cairn can do".
resource "aws_iam_role" "lambda" {
  for_each = toset(["account", "ingest", "query", "rollup"])

  name               = "cairn-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  for_each = aws_iam_role.lambda

  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# ---------------------------------------------------------------------------
# ingest: write events, read the hashing secret. Nothing else.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ingest" {
  statement {
    sid       = "WriteEventsOnly"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.cairn.arn]
  }

  statement {
    sid       = "ReadHashingSecret"
    actions   = ["ssm:GetParameter"]
    resources = [local.salt_parameter_arn]
  }

  # ssm:GetParameter alone returns ciphertext for a SecureString. Decryption is
  # a separate permission on the key, and omitting it is the usual cause of an
  # AccessDenied on a parameter the role can obviously see.
  statement {
    sid       = "DecryptHashingSecret"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_alias.ssm.target_key_arn]
  }
}

resource "aws_iam_role_policy" "ingest" {
  name   = "cairn-ingest"
  role   = aws_iam_role.lambda["ingest"].id
  policy = data.aws_iam_policy_document.ingest.json
}

# ---------------------------------------------------------------------------
# query: read only
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "query" {
  statement {
    sid       = "ReadAggregatesAndLiveEvents"
    actions   = ["dynamodb:Query"]
    resources = [aws_dynamodb_table.cairn.arn]
  }

  # Authorization reads two single rows per request: the site's ownership row
  # and, for a private site, the caller's session. Without GetItem the handler
  # compiles and then denies every request at run time.
  statement {
    sid       = "ReadSiteOwnershipAndSessions"
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.cairn.arn]
  }
}

# ---------------------------------------------------------------------------
# account: the only writer of account rows
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "account" {
  statement {
    sid = "ManageAccountsAndSites"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
    ]
    resources = [aws_dynamodb_table.cairn.arn]
  }
}

resource "aws_iam_role_policy" "account" {
  name   = "cairn-account"
  role   = aws_iam_role.lambda["account"].id
  policy = data.aws_iam_policy_document.account.json
}

resource "aws_iam_role_policy" "query" {
  name   = "cairn-query"
  role   = aws_iam_role.lambda["query"].id
  policy = data.aws_iam_policy_document.query.json
}

# ---------------------------------------------------------------------------
# rollup: read raw rows, write aggregates, archive to S3
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "rollup" {
  statement {
    sid = "ReadRawAndWriteAggregates"
    actions = [
      "dynamodb:Query",
      "dynamodb:BatchWriteItem",
      "dynamodb:PutItem",
      # Reads the site registry, so a customer registered since the last
      # deploy is aggregated without a Terraform apply.
      "dynamodb:GetItem",
    ]
    resources = [aws_dynamodb_table.cairn.arn]
  }

  # Scoped to the `raw/` prefix, and PutObject only. The rollup overwrites its
  # own hourly objects by design, but it has no DeleteObject, so a bug cannot
  # wipe the archive.
  statement {
    sid       = "ArchiveRawEvents"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*"]
  }
}

resource "aws_iam_role_policy" "rollup" {
  name   = "cairn-rollup"
  role   = aws_iam_role.lambda["rollup"].id
  policy = data.aws_iam_policy_document.rollup.json
}
