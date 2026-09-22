# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
#
# Why not Lambda Function URLs, which are free where this costs $1 per million
# requests after the first year:
#
# Function URLs can be locked to CloudFront with Origin Access Control, and OAC
# signs each origin request with SigV4. But SigV4 covers the request body, and
# CloudFront does not compute the body hash. AWS requires the *client* to send
# `x-amz-content-sha256` itself, and Lambda rejects unsigned payloads outright.
#
# The client here is `navigator.sendBeacon`, which cannot set request headers at
# all. So every POST arrives with a signature that cannot match, and the
# endpoint returns 403 for exactly the requests it exists to serve. No amount of
# policy tuning fixes it; the constraint is structural.
#
# At this traffic the price difference is roughly a penny a month, which was
# never worth trading away a working ingest path.
#
# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html

resource "aws_apigatewayv2_api" "cairn" {
  name          = "cairn"
  description   = "Ingest and stats endpoints, fronted by CloudFront"
  protocol_type = "HTTP"
}

# `$default` deploys at the API root, so paths reaching the origin are `/e` and
# `/api/stats/...` rather than `/prod/e`. That keeps CloudFront from having to
# rewrite paths, and keeps the Lambda's own path parsing honest.
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.cairn.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    # A ceiling, not an expectation. The account-level Lambda concurrency limit
    # is the real backstop, but a public write endpoint should have a number on
    # it that is small enough to notice and large enough never to hit.
    throttling_burst_limit = 200
    throttling_rate_limit  = 100
  }
}

resource "aws_apigatewayv2_integration" "ingest" {
  api_id                 = aws_apigatewayv2_api.cairn.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.cairn["ingest"].invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "query" {
  api_id                 = aws_apigatewayv2_api.cairn.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.cairn["query"].invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_integration" "account" {
  api_id                 = aws_apigatewayv2_api.cairn.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.cairn["account"].invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "ingest" {
  api_id    = aws_apigatewayv2_api.cairn.id
  route_key = "POST /e"
  target    = "integrations/${aws_apigatewayv2_integration.ingest.id}"
}

# sendBeacon posts `text/plain`, which is CORS-simple and never preflighted, so
# this route exists only for the tracker's `fetch` fallback path.
resource "aws_apigatewayv2_route" "ingest_options" {
  api_id    = aws_apigatewayv2_api.cairn.id
  route_key = "OPTIONS /e"
  target    = "integrations/${aws_apigatewayv2_integration.ingest.id}"
}

resource "aws_apigatewayv2_route" "stats" {
  api_id    = aws_apigatewayv2_api.cairn.id
  route_key = "GET /api/stats/{site}"
  target    = "integrations/${aws_apigatewayv2_integration.query.id}"
}

# Listed one by one rather than behind a `{proxy+}`, so a route that is not
# implemented is a 404 from API Gateway instead of a Lambda invocation that has
# to decide it was never a real route.
resource "aws_apigatewayv2_route" "account" {
  for_each = toset([
    "POST /api/auth/signup",
    "POST /api/auth/login",
    "POST /api/auth/logout",
    "GET /api/auth/me",
    "GET /api/sites",
    "POST /api/sites",
    "PATCH /api/sites/{site}",
    "DELETE /api/sites/{site}",
    "GET /api/billing/summary",
    "POST /api/billing/checkout",
    "POST /api/billing/webhook",
  ])

  api_id    = aws_apigatewayv2_api.cairn.id
  route_key = each.value
  target    = "integrations/${aws_apigatewayv2_integration.account.id}"
}

resource "aws_lambda_permission" "apigw_account" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cairn["account"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.cairn.execution_arn}/*/*"
}

# Scoped to this API. Without the source ARN condition any API Gateway in any
# account could invoke these functions.
resource "aws_lambda_permission" "apigw_ingest" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cairn["ingest"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.cairn.execution_arn}/*/*"
}

resource "aws_lambda_permission" "apigw_query" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cairn["query"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.cairn.execution_arn}/*/*"
}
