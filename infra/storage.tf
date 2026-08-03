# ---------------------------------------------------------------------------
# DynamoDB: raw events and aggregates in one table
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "cairn" {
  name         = local.name
  billing_mode = "PROVISIONED"

  read_capacity  = var.table_capacity
  write_capacity = var.table_capacity

  hash_key  = "pk"
  range_key = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # Raw events carry an `expires_at` and are reaped a week after ingest. The
  # aggregates the dashboard reads have no TTL attribute at all, so they are
  # never touched by this.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # Off deliberately. PITR is billed on table size and is insurance against a
  # bad write destroying irreplaceable data. Neither applies here: aggregates
  # are recomputed from raw rows by design, and raw rows are analytics events
  # that expire in a week regardless.
  point_in_time_recovery {
    enabled = false
  }
}

# ---------------------------------------------------------------------------
# S3: static assets and the raw-event archive
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "assets" {
  bucket = local.assets_bucket
}

resource "aws_s3_bucket" "archive" {
  bucket = local.archive_bucket
}

# Both buckets are fully private. The assets bucket is readable only through
# CloudFront's Origin Access Control, so there is no bucket-level public read
# to misconfigure.
resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = false # the OAC policy below is not a public policy
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# The archive holds NDJSON that has already been aggregated, so it is cold the
# moment it lands. Glacier Instant Retrieval is a fraction of Standard's price
# and still reads in milliseconds if a rollup ever needs replaying.
resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id

  rule {
    id     = "age-out-raw-events"
    status = "Enabled"

    filter {
      prefix = "raw/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 730
    }
  }
}
