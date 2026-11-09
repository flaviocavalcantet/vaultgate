# Local environment: the AWS provider points at LocalStack, so `terraform apply`
# runs the same modules a real AWS environment would, at zero cost.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

locals {
  region = "ap-northeast-1"
  # The services, each with its own AWS identity (M10, TM-2).
  services = toset(["api", "gateway", "scanner"])
}

provider "aws" {
  region                      = local.region
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
    iam = "http://localhost:4566"
  }
}

module "storage" {
  source = "../../modules/storage"
  name   = "vaultgate-local"
}

module "scanning" {
  source = "../../modules/scanning"
  name   = "vaultgate-local"
}

# One least-privilege policy per service, and here one IAM user each, whose key the
# service gets from OpenBao (scripts/service_secrets.py seed-aws). LocalStack doesn't
# enforce IAM: locally this is the plumbing; the policies are what AWS would enforce.
module "access" {
  source      = "../../modules/access"
  name        = "vaultgate-local"
  region      = local.region
  bucket_arn  = module.storage.bucket_arn
  kms_key_arn = module.storage.kms_key_arn
  queue_arn   = module.scanning.queue_arn
}

resource "aws_iam_user" "service" {
  for_each = local.services
  name     = "vaultgate-local-${each.key}"
}

resource "aws_iam_user_policy_attachment" "service" {
  for_each   = local.services
  user       = aws_iam_user.service[each.key].name
  policy_arn = module.access.policy_arns[each.key]
}

resource "aws_iam_access_key" "service" {
  for_each = local.services
  user     = aws_iam_user.service[each.key].name
}

output "bucket_name" { value = module.storage.bucket_name }
output "kms_alias" { value = module.storage.kms_alias }
output "scan_queue_url" { value = module.scanning.queue_url }

# Each service's key, by service, as the AWS SDKs' credentials file reads it.
output "service_credentials" {
  sensitive = true
  value = {
    for service, key in aws_iam_access_key.service : service =>
    "[default]\naws_access_key_id = ${key.id}\naws_secret_access_key = ${key.secret}\n"
  }
}
