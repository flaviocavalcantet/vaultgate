# Encrypted object storage for vault files.
# Each file is encrypted client-side with its own data key (envelope encryption);
# this KMS key only wraps those data keys, and S3 adds server-side encryption on top.

variable "name" {
  type        = string
  description = "Name prefix for created resources."
}

resource "aws_kms_key" "vault" {
  description             = "${var.name} key-encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "vault" {
  bucket        = "${var.name}-vault"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.vault.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }
}

output "bucket_name" { value = aws_s3_bucket.vault.bucket }
output "kms_key_arn" { value = aws_kms_key.vault.arn }
