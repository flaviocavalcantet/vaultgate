# OpenBao, VaultGate's certificate authority and secret store (M9, ADR 0012). One node,
# integrated storage, TLS only. Everything below is in git; the two things that are not
# are mounted from Secrets that `make k3d-up` creates: the server's TLS certificate (from
# the offline root, scripts/pki.py) and the seal key.

ui            = false
disable_mlock = true # as recommended with integrated storage
api_addr      = "https://openbao.openbao.svc:8200"
cluster_addr  = "https://127.0.0.1:8201"

listener "tcp" {
  address          = "0.0.0.0:8200"
  cluster_address  = "127.0.0.1:8201"
  tls_cert_file    = "/openbao/tls/tls.crt"
  tls_key_file     = "/openbao/tls/tls.key"
  tls_min_version  = "tls13"
  tls_auto_reload  = true # a renewed certificate (scripts/pki.py openbao-tls) without a restart
}

storage "raft" {
  path    = "/openbao/data"
  node_id = "openbao-0"
}

# Auto-unseal with a static key from a Secret: for the local cluster only, where the
# cluster is its own source of trust anyway. Elsewhere the seal is a cloud KMS (awskms),
# so unsealing needs the KMS and the storage alone is useless (ADR 0012).
seal "static" {
  current_key_id = "local-1"
  current_key    = "file:///openbao/unseal/key"
}

# The audit log, on stdout (so in Loki). Declared here: OpenBao doesn't let its API
# create audit devices.
audit "file" "stdout" {
  description = "Every request and response, with secrets HMAC'd"
  options {
    file_path = "stdout"
  }
}

# Self-initialization, once, on the first start of an empty storage. The root token it
# uses is revoked afterwards: nobody ever holds one. A failed request stops it, and it
# isn't retried: fix the request, then start again from empty storage. What it sets up:
# - the `pki` mount, which holds the intermediate CA, whose key is generated inside
#   OpenBao and never leaves it;
# - Kubernetes logins, and the one role the ceremony needs (scripts/pki.py intermediate):
#   a short-lived token for the `pki-ceremony` service account, allowed to have the
#   intermediate's CSR generated, its signed certificate installed and made the default
#   issuer, and the token revoked when done; nothing else (no `default` policy).
initialize "pki" {
  request "mount" {
    operation = "update"
    path      = "sys/mounts/pki"
    data = {
      type        = "pki"
      description = "VaultGate's intermediate CA, signed by the offline root"
      # The longest certificate this mount issues; roles set shorter ones.
      config = { max_lease_ttl = "2160h" }
    }
  }
  request "urls" {
    operation = "update"
    path      = "pki/config/urls"
    data = {
      issuing_certificates    = ["https://openbao.openbao.svc:8200/v1/pki/ca"]
      crl_distribution_points = ["https://openbao.openbao.svc:8200/v1/pki/crl"]
    }
  }
}

initialize "auth" {
  request "kubernetes" {
    operation = "update"
    path      = "sys/auth/kubernetes"
    data      = { type = "kubernetes" }
  }
  # Inside the pod: the API server's address; its CA and the token to review logins come
  # from OpenBao's own service account (allowed to by system:auth-delegator).
  request "kubernetes-config" {
    operation = "update"
    path      = "auth/kubernetes/config"
    data      = { kubernetes_host = "https://kubernetes.default.svc" }
  }
  request "ceremony-policy" {
    operation = "update"
    path      = "sys/policies/acl/pki-ceremony"
    data = {
      policy = <<EOT
path "pki/intermediate/generate/internal" { capabilities = ["update"] }
path "pki/intermediate/set-signed" { capabilities = ["update"] }
path "pki/issuers" { capabilities = ["list"] }
path "pki/issuer/+" { capabilities = ["read"] }
path "pki/config/issuers" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
EOT
    }
  }
  request "ceremony-role" {
    operation = "update"
    path      = "auth/kubernetes/role/pki-ceremony"
    data = {
      bound_service_account_names      = ["pki-ceremony"]
      bound_service_account_namespaces = ["openbao"]
      audience                         = "openbao"
      token_policies                   = ["pki-ceremony"]
      token_ttl                        = "10m"
      token_max_ttl                    = "10m"
      token_no_default_policy          = true
    }
  }
}
