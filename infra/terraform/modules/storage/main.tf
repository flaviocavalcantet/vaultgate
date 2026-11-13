# Encrypted object storage for vault files.
# Each file is encrypted client-side with its own data key (envelope encryption);
# this KMS key only wraps those data keys, and S3 adds server-side encryption on top.

variable "name" {
  type        = string
  description = "Name prefix for created resources."
}

variable "deleted_object_days" {
  type        = number
  default     = 1
  description = "Days the versions of a deleted file's object are kept before S3 expires them (ADR 0020)."
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
#
# A deleted file's object (ADR 0020): the gateway's delete leaves a delete marker over
# its version, which S3 expires after deleted_object_days, and then the marker. File
# keys are never written twice, so only a deleted file's object has a noncurrent
# version. Its wrapped key went with the file's row, so it can't be decrypted meanwhile.
resource "aws_s3_bucket_lifecycle_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id     = "expire-deleted-files"
    status = "Enabled"
    filter { prefix = "files/" }
    noncurrent_version_expiration { noncurrent_days = var.deleted_object_days }
    expiration { expired_object_delete_marker = true }
  }

  depends_on = [aws_s3_bucket_versioning.vault]
}

output "bucket_name" { value = aws_s3_bucket.vault.bucket }
output "bucket_arn" { value = aws_s3_bucket.vault.arn }
output "kms_key_arn" { value = aws_kms_key.vault.arn }
output "kms_alias" { value = aws_kms_alias.vault.name }
