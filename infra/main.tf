provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "cairn"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

# The AWS-managed key that encrypts SSM SecureStrings. Reading a SecureString
# needs kms:Decrypt on this key in addition to ssm:GetParameter, which is the
# usual reason a Lambda gets AccessDenied on a parameter it can plainly see.
data "aws_kms_alias" "ssm" {
  name = "alias/aws/ssm"
}

locals {
  name = "cairn"

  # S3 bucket names are globally unique across every AWS account on earth, so
  # `cairn-assets` was taken years ago. The account ID makes them unique without
  # introducing random state.
  assets_bucket  = "cairn-assets-${data.aws_caller_identity.current.account_id}"
  archive_bucket = "cairn-archive-${data.aws_caller_identity.current.account_id}"

  # Built rather than looked up, so Terraform never reads the secret's value and
  # therefore never writes it into state.
  salt_parameter_arn = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.salt_parameter_name}"

  # Where `cargo lambda build --release --arm64 --output-format zip` leaves its
  # artifacts.
  lambda_dir = "${path.module}/../target/lambda"

  common_env = {
    CAIRN_TABLE = aws_dynamodb_table.cairn.name
  }
}
