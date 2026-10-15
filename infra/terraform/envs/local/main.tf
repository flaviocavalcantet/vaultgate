# Local environment: the AWS provider points at LocalStack, so `terraform apply`
# runs the same modules a real AWS environment would, at zero cost.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region                      = "ap-northeast-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3  = "http://localhost:4566"
    kms = "http://localhost:4566"
    sqs = "http://localhost:4566"
  }
}

module "storage" {
  source = "../../modules/storage"
  name   = "vaultgate-local"
}

output "bucket_name" { value = module.storage.bucket_name }
