# One least-privilege IAM policy per service (M10, TM-2 in docs/threat-model.md): each
# holds what its own code calls, and nothing of the others'.
#
# - The API sends scan requests.
# - The gateway writes, reads and deletes the vault's objects, and has the vault key
#   generate and unwrap their data keys.
# - The scanner reads objects, unwraps their data keys, and consumes the scan queue. It
#   parses untrusted files, so it gets no write or delete.
#
# The vault key is used two ways, and each is allowed only as it happens. Directly, with
# a file's encryption context (file_id), so a data key unwraps only for its own file. And
# by S3 on the service's behalf, for the bucket's default encryption (SSE-KMS).
#
# Attach the policies to whatever each service runs as: IAM roles for service accounts
# in EKS, or, as the local environment does, one IAM user per service.

variable "name" {
  type        = string
  description = "Name prefix for created resources."
}

variable "region" {
  type        = string
  description = "The region S3 runs in, for the key's kms:ViaService condition."
}

variable "bucket_arn" {
  type        = string
  description = "The vault bucket; services reach only its objects under files/."
}

variable "kms_key_arn" {
  type        = string
  description = "The vault key."
}

variable "queue_arn" {
  type        = string
  description = "The scan request queue."
}

locals {
  objects = "${var.bucket_arn}/files/*"

  # Directly: only with a file's encryption context, and nothing but file_id in it.
  for_a_file = {
    "ForAllValues:StringEquals" = { "kms:EncryptionContextKeys" = ["file_id"] }
    "Null"                      = { "kms:EncryptionContextKeys" = "false" }
  }
  # By S3, for the bucket's default encryption.
  via_s3 = { StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" } }

  policies = {
    api = [
      { Sid = "SendScanRequests", Action = ["sqs:SendMessage"], Resource = [var.queue_arn] },
    ]
    gateway = [
      {
        Sid = "StoreAndServeObjects"
        Action = [
          "s3:PutObject", # a multipart upload's start, parts and completion
          "s3:AbortMultipartUpload",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion", # an object the API refused to record
        ]
        Resource = [local.objects]
      },
      {
        Sid       = "FileDataKeys"
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = [var.kms_key_arn]
        Condition = local.for_a_file
      },
      {
        Sid       = "BucketEncryption"
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource  = [var.kms_key_arn]
        Condition = local.via_s3
      },
    ]
    scanner = [
      { Sid = "ReadObjects", Action = ["s3:GetObject"], Resource = [local.objects] },
      {
        Sid       = "UnwrapFileDataKeys"
        Action    = ["kms:Decrypt"]
        Resource  = [var.kms_key_arn]
        Condition = local.for_a_file
      },
      {
        Sid       = "BucketEncryption"
        Action    = ["kms:Decrypt"]
        Resource  = [var.kms_key_arn]
        Condition = local.via_s3
      },
      {
        Sid      = "ConsumeScanRequests"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"]
        Resource = [var.queue_arn]
      },
    ]
  }

  documents = {
    for service, statements in local.policies : service => jsonencode({
      Version   = "2012-10-17"
      Statement = [for s in statements : merge({ Effect = "Allow" }, s)]
    })
  }
}

resource "aws_iam_policy" "service" {
  for_each    = local.documents
  name        = "${var.name}-${each.key}"
  description = "VaultGate's ${each.key}: what its code calls, nothing more"
  policy      = each.value
}

output "policy_arns" {
  value       = { for service, policy in aws_iam_policy.service : service => policy.arn }
  description = "Each service's policy, by service (api, gateway, scanner)."
}

output "policy_documents" {
  value       = local.documents
  description = "The same policies' JSON, by service."
}

output "actions" {
  value = {
    for service, statements in local.policies :
    service => sort(distinct(flatten([for s in statements : s.Action])))
  }
  description = "Every action each service may take, by service."
}
