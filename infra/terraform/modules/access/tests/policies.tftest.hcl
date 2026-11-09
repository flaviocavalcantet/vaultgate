# Each service holds what its code calls and none of the others' rights (M10, TM-2).
# `terraform test` in this module; the AWS provider is mocked, the policies are not.

mock_provider "aws" {}

variables {
  name        = "test"
  region      = "ap-northeast-1"
  bucket_arn  = "arn:aws:s3:::vault"
  kms_key_arn = "arn:aws:kms:ap-northeast-1:000000000000:key/vault"
  queue_arn   = "arn:aws:sqs:ap-northeast-1:000000000000:scans"
}

run "the_api_only_sends_scan_requests" {
  command = plan
  assert {
    condition     = output.actions["api"] == tolist(["sqs:SendMessage"])
    error_message = "the API may do more than send scan requests: ${jsonencode(output.actions["api"])}"
  }
}

run "the_scanner_writes_and_deletes_nothing" {
  command = plan
  assert {
    condition = output.actions["scanner"] == tolist(sort([
      "kms:Decrypt", "s3:GetObject",
      "sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:ReceiveMessage",
    ]))
    error_message = "the scanner's rights changed: ${jsonencode(output.actions["scanner"])}"
  }
}

run "the_gateway_never_touches_the_queue" {
  command = plan
  assert {
    condition     = alltrue([for a in output.actions["gateway"] : !startswith(a, "sqs:")])
    error_message = "the gateway may use the scan queue"
  }
  assert {
    condition     = !contains(output.actions["gateway"], "s3:ListBucket")
    error_message = "the gateway may list the bucket"
  }
}

run "no_wildcards_and_every_key_use_has_a_condition" {
  command = plan
  assert {
    condition = alltrue(flatten([
      for doc in values(output.policy_documents) : [
        for s in jsondecode(doc).Statement : [for a in s.Action : !strcontains(a, "*")]
      ]
    ]))
    error_message = "an action has a wildcard"
  }
  assert {
    condition = alltrue(flatten([
      for doc in values(output.policy_documents) : [
        for s in jsondecode(doc).Statement : can(s.Condition)
        if anytrue([for a in s.Action : startswith(a, "kms:")])
      ]
    ]))
    error_message = "a statement uses the vault key without a condition"
  }
  assert {
    condition = alltrue(flatten([
      for doc in values(output.policy_documents) : [
        for s in jsondecode(doc).Statement : [for r in s.Resource : r == "${var.bucket_arn}/files/*"]
        if anytrue([for a in s.Action : startswith(a, "s3:")])
      ]
    ]))
    error_message = "a service reaches more of the bucket than its files"
  }
}
