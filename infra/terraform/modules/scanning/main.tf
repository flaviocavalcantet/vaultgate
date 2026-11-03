# Queue of PII scan requests. The API sends one per completed upload (and resends
# the ones that got no result); the scanner worker consumes them.
#
# A message the worker cannot finish (the API, KMS or S3 unreachable, a crash) comes
# back after the visibility timeout; after max_receive_count deliveries it moves to
# the dead-letter queue, where it waits to be looked at. The API keeps its own record
# and marks a file unscannable once its resends run out, so nothing is lost or
# treated as clean when a message ends up there.

variable "name" {
  type        = string
  description = "Name prefix for created resources."
}

variable "visibility_timeout_seconds" {
  type        = number
  default     = 120
  description = "How long a received message stays hidden; the worker renews it while it scans (VAULTGATE_SCAN_VISIBILITY_SECONDS)."
}

variable "max_receive_count" {
  type        = number
  default     = 5
  description = "Deliveries before a message moves to the dead-letter queue."
}

resource "aws_sqs_queue" "scans_dlq" {
  name                      = "${var.name}-scans-dlq"
  message_retention_seconds = 1209600 # 14 days, the maximum: time to investigate
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "scans" {
  name                       = "${var.name}-scans"
  visibility_timeout_seconds = var.visibility_timeout_seconds
  message_retention_seconds  = 345600 # 4 days
  receive_wait_time_seconds  = 20     # long polling
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.scans_dlq.arn
    maxReceiveCount     = var.max_receive_count
  })
}

# Only the scan queue may send to the dead-letter queue.
resource "aws_sqs_queue_redrive_allow_policy" "scans_dlq" {
  queue_url = aws_sqs_queue.scans_dlq.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.scans.arn]
  })
}

output "queue_url" { value = aws_sqs_queue.scans.url }
output "queue_arn" { value = aws_sqs_queue.scans.arn }
output "dead_letter_queue_url" { value = aws_sqs_queue.scans_dlq.url }
