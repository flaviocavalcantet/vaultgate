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

# Stable name for the gateway's configuration (VAULTGATE_KMS_KEY_ID).
resource "aws_kms_alias" "vault" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.vault.key_id
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

# Parts of a multipart upload that was never completed or aborted (gateway crash,
# lost connection to S3) are invisible but billed; S3 deletes them after a day.
resource "aws_s3_bucket_lifecycle_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

output "bucket_name" { value = aws_s3_bucket.vault.bucket }
output "kms_key_arn" { value = aws_kms_key.vault.arn }
output "kms_alias" { value = aws_kms_alias.vault.name }
