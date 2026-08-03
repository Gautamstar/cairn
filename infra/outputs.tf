output "cloudfront_domain" {
  description = "The distribution's hostname. Everything Cairn serves lives here."
  value       = aws_cloudfront_distribution.cairn.domain_name
}

output "dashboard_url" {
  value = "https://${aws_cloudfront_distribution.cairn.domain_name}/"
}

output "tracker_tag" {
  description = "Paste this into the <head> of each site being measured."
  value       = <<-EOT
    <script defer src="https://${aws_cloudfront_distribution.cairn.domain_name}/cairn.js" data-site="SITE"></script>
  EOT
}

output "stats_api" {
  description = "Read API. Append ?days=N to change the range."
  value       = "https://${aws_cloudfront_distribution.cairn.domain_name}/api/stats/SITE"
}

output "ingest_endpoint" {
  description = "Where the tracker posts. Useful for a curl smoke test."
  value       = "https://${aws_cloudfront_distribution.cairn.domain_name}/e"
}

output "table_name" {
  value = aws_dynamodb_table.cairn.name
}

output "assets_bucket" {
  description = "Sync the tracker script and dashboard here."
  value       = aws_s3_bucket.assets.bucket
}

output "archive_bucket" {
  value = aws_s3_bucket.archive.bucket
}
