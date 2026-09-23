locals {
  functions = {
    # 128 MB is the floor, and Rust is the reason it is enough: the handler
    # allocates one string per request and holds no runtime. Whether more memory
    # pays for itself through the proportional CPU increase is exactly what the
    # benchmark is for, so this is a knob, not a conclusion.
    ingest = {
      memory  = 128
      timeout = 5
      env = {
        CAIRN_TABLE         = aws_dynamodb_table.cairn.name
        CAIRN_SECRET_PARAM  = var.salt_parameter_name
        CAIRN_ORIGIN_SECRET = random_password.origin_secret.result
      }
    }

    query = {
      memory  = 256
      timeout = 10
      env = {
        CAIRN_TABLE         = aws_dynamodb_table.cairn.name
        CAIRN_ORIGIN_SECRET = random_password.origin_secret.result
      }
    }

    # Argon2 is deliberately expensive, and on Lambda CPU scales with memory,
    # so more memory here makes a login finish sooner and can cost less in
    # GB-seconds than the 128 MB floor would. Signups are rare; this is not on
    # any hot path.
    account = {
      memory  = 512
      timeout = 10
      env = {
        CAIRN_TABLE         = aws_dynamodb_table.cairn.name
        CAIRN_ORIGIN_SECRET = random_password.origin_secret.result
      }
    }

    # Holds a HashSet of visitor IDs per dimension for a whole day, and walks 48
    # hour-partitions per run, so it gets both more memory and a much longer
    # timeout than the request handlers.
    rollup = {
      memory  = 512
      timeout = 300
      env = {
        CAIRN_TABLE          = aws_dynamodb_table.cairn.name
        CAIRN_SITES          = join(",", var.sites)
        CAIRN_ARCHIVE_BUCKET = aws_s3_bucket.archive.bucket
      }
    }
  }
}

resource "aws_lambda_function" "cairn" {
  for_each = local.functions

  function_name = "cairn-${each.key}"
  role          = aws_iam_role.lambda[each.key].arn

  # `provided.al2023` is the OS-only runtime: there is no language runtime to
  # boot, the binary is the process. Combined with arm64 Graviton, which is
  # around 20% cheaper per GB-second, this is where the cold-start and cost
  # numbers in the README come from.
  runtime       = "provided.al2023"
  handler       = "bootstrap"
  architectures = ["arm64"]

  # Built by `cargo lambda build --release --arm64 --output-format zip`, which
  # must run before `terraform plan`. Terraform reads these files at plan time,
  # so a missing zip is a plan-time error rather than a confusing apply failure.
  filename         = "${local.lambda_dir}/cairn-${each.key}/bootstrap.zip"
  source_code_hash = filebase64sha256("${local.lambda_dir}/cairn-${each.key}/bootstrap.zip")

  memory_size = each.value.memory
  timeout     = each.value.timeout

  environment {
    variables = each.value.env
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

# Created explicitly so retention is bounded. Lambda creates these implicitly on
# first invocation with retention set to "never expire", which is the quiet way
# a free-tier account starts accruing charges six months later.
resource "aws_cloudwatch_log_group" "lambda" {
  for_each = local.functions

  name              = "/aws/lambda/cairn-${each.key}"
  retention_in_days = var.log_retention_days
}

# HTTP entry points live in apigateway.tf. They were Lambda Function URLs
# behind CloudFront Origin Access Control until that turned out to be
# structurally incompatible with this workload; see the note there.

# ---------------------------------------------------------------------------
# Hourly rollup
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "rollup" {
  name        = "cairn-rollup-hourly"
  description = "Recompute today's and yesterday's aggregates from raw events"

  # Hourly. This interval is the dashboard's freshness for everything except the
  # live counter, so a pageview can sit invisible in the charts for up to an
  # hour. That is a deliberate trade rather than a limit: shortening it is a
  # one-line change and stays inside the free tier, and the job recomputes
  # rather than increments, so running it more often is safe by construction.
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "rollup" {
  rule      = aws_cloudwatch_event_rule.rollup.name
  target_id = "cairn-rollup"
  arn       = aws_lambda_function.cairn["rollup"].arn
}

# EventBridge can retry on failure, and a duplicate run is harmless here only
# because the rollup recomputes rather than increments. With incrementing
# counters this schedule would be a correctness hazard.
resource "aws_lambda_permission" "events_rollup" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cairn["rollup"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rollup.arn
}
