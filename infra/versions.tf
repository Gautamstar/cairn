terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State is local and gitignored. That is the right call for a single
  # operator: an S3 backend with a DynamoDB lock table is real infrastructure
  # to protect state that only one machine ever writes. It becomes wrong the
  # moment a second person or a CI runner needs to apply, which is the point to
  # revisit this.
}
