# Proves to the handlers that a request came through CloudFront rather than
# straight to the publicly reachable API Gateway endpoint.
#
# This value is stored in Terraform state and in the CloudFront config as
# plaintext, so it is not a strong secret and is not treated as one. It is worth
# what it protects: the integrity of pageview counts. Rotating it is a
# `terraform taint` and an apply.
#
# `special = false` because the value travels in an HTTP header, where
# punctuation invites encoding bugs for no added entropy that length cannot buy.
resource "random_password" "origin_secret" {
  length  = 48
  special = false
}

resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "cairn-assets"
  description                       = "Lets CloudFront read the private assets bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

# Exactly the three headers the ingest handler reads, and nothing else.
#
# Host is excluded, which is why this is a whitelist rather than one of the
# "all viewer headers" managed policies. API Gateway routes on the Host it
# receives, so forwarding the viewer's Host makes it fail to match its own API.
#
# CloudFront-Viewer-Address carries the address CloudFront observed on the
# connection it terminated. CloudFront overwrites any client-supplied value, so
# unlike X-Forwarded-For it cannot be forged, and unlike X-Forwarded-For its
# meaning does not shift when another proxy joins the chain.
resource "aws_cloudfront_origin_request_policy" "ingest" {
  name    = "cairn-ingest"
  comment = "User agent, viewer country, viewer address"

  headers_config {
    header_behavior = "whitelist"

    headers {
      items = ["user-agent", "cloudfront-viewer-country", "cloudfront-viewer-address"]
    }
  }

  cookies_config {
    cookie_behavior = "none"
  }

  query_strings_config {
    query_string_behavior = "none"
  }
}

# Account traffic. A whitelist, like the policies above, and for a sharper
# reason than tidiness: forwarding every viewer header would forward `Host`,
# and API Gateway identifies the API by its Host header, so a request arriving
# as `<distribution>.cloudfront.net` is refused with a 403 before any handler
# runs. Only what the account handler reads is sent.
resource "aws_cloudfront_origin_request_policy" "account" {
  name    = "cairn-account"
  comment = "Content type, Stripe's signature, and the session cookie"

  headers_config {
    header_behavior = "whitelist"

    # stripe-signature is how the billing webhook proves a request came from
    # Stripe. Leave it out of this list and every webhook fails verification.
    headers {
      items = ["content-type", "stripe-signature"]
    }
  }

  cookies_config {
    cookie_behavior = "whitelist"

    cookies {
      items = ["cairn_session"]
    }
  }

  query_strings_config {
    query_string_behavior = "none"
  }
}

resource "aws_cloudfront_origin_request_policy" "query" {
  name    = "cairn-query"
  comment = "Nothing beyond the cache key, which already carries the day range"

  headers_config {
    header_behavior = "none"
  }

  # The session cookie has to reach the handler or every private site is
  # denied. Only this one cookie is forwarded, so an unrelated cookie on the
  # domain cannot fragment the cache.
  cookies_config {
    cookie_behavior = "whitelist"
    cookies {
      items = ["cairn_session"]
    }
  }

  query_strings_config {
    query_string_behavior = "none"
  }
}

# A minute of staleness is invisible on a daily chart and removes almost every
# repeat Lambda invocation from someone leaving the dashboard open. `days` is in
# the cache key because it changes the response; anything in the cache key is
# forwarded to the origin automatically, which is why the origin request policy
# above needs no query string config of its own.
resource "aws_cloudfront_cache_policy" "stats" {
  name        = "cairn-stats"
  comment     = "Short-lived caching for the stats API"
  min_ttl     = 0
  default_ttl = 60
  max_ttl     = 300

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_gzip   = true
    enable_accept_encoding_brotli = true

    headers_config {
      header_behavior = "none"
    }

    # In the cache key, not just forwarded: a private site's response depends
    # on who asked. Anonymous readers of a public site still share one entry,
    # because they send no cookie at all.
    cookies_config {
      cookie_behavior = "whitelist"
      cookies {
        items = ["cairn_session"]
      }
    }

    query_strings_config {
      query_string_behavior = "whitelist"

      query_strings {
        items = ["days"]
      }
    }
  }
}

resource "aws_cloudfront_distribution" "cairn" {
  enabled             = true
  comment             = "cairn"
  default_root_object = "index.html"

  # North America and Europe only. Visitors elsewhere are still served, just
  # from a farther edge, and country stats are unaffected since the viewer
  # country is resolved wherever the request lands.
  price_class = "PriceClass_100"

  origin {
    origin_id                = "assets"
    domain_name              = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  # One origin for both dynamic paths. The API routes `/e` and
  # `/api/stats/{site}` to different Lambdas itself, so CloudFront only needs
  # separate cache behaviors, not separate origins.
  origin {
    origin_id   = "api"
    domain_name = replace(aws_apigatewayv2_api.cairn.api_endpoint, "https://", "")

    # Added by CloudFront to every origin request regardless of the origin
    # request policy, and not visible to or settable by the viewer.
    custom_header {
      name  = "x-cairn-origin"
      value = random_password.origin_secret.result
    }

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # Everything not matched below is a static file: the tracker script and the
  # dashboard.
  default_cache_behavior {
    target_origin_id       = "assets"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = data.aws_cloudfront_cache_policy.optimized.id
    compress               = true
  }

  ordered_cache_behavior {
    path_pattern           = "/e"
    target_origin_id       = "api"
    viewer_protocol_policy = "https-only"

    # CloudFront requires the full write set to be listed before it will allow
    # POST at all.
    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.ingest.id

    # The response is an empty 204. There is nothing to compress.
    compress = false
  }

  # Ahead of /api/* deliberately: CloudFront takes the first matching pattern,
  # and these routes need POST, PATCH and DELETE, which /api/* does not allow.
  ordered_cache_behavior {
    path_pattern           = "/api/auth/*"
    target_origin_id       = "api"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.account.id
    compress                 = true
  }

  # Stripe's webhook is a POST and must arrive byte-for-byte, with its
  # Stripe-Signature header, or the signature cannot verify. The account
  # origin-request policy whitelists that header; caching is off.
  ordered_cache_behavior {
    path_pattern           = "/api/billing/*"
    target_origin_id       = "api"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.account.id

    # Compression would not change the bytes the handler sees, but nothing
    # here is large enough to be worth it, and the webhook's body is the one
    # place on this API where exact bytes matter.
    compress = false
  }

  ordered_cache_behavior {
    path_pattern           = "/api/sites*"
    target_origin_id       = "api"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.account.id
    compress                 = true
  }

  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "api"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]

    cache_policy_id          = aws_cloudfront_cache_policy.stats.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.query.id
    compress                 = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Grants read to this distribution specifically, not to CloudFront generally.
# Without the SourceArn condition, any CloudFront distribution in any AWS
# account could read the bucket.
data "aws_iam_policy_document" "assets" {
  statement {
    sid       = "AllowCloudFrontRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cairn.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = data.aws_iam_policy_document.assets.json
}
