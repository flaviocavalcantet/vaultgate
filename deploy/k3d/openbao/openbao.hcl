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
#   issuer, and the token revoked when done; nothing else (no `default` policy);
# - the role cert-manager signs service certificates with, and its login: the
#   openbao-issuer service account in cert-manager's namespace, which may sign under
#   that role only;
# - the `pki-nodes` mount (M11, ADR 0014): the nodes' intermediate CA, from the same
#   ceremony, its revocation lists and OCSP, and the role node certificates are signed
#   under.
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
  # Server certificates for the cluster's services, signed from a CSR (cert-manager's
  # key stays with cert-manager): DNS names under svc and cluster.local, and localhost,
  # for a day by default and three at most. No IP addresses, wildcards or other names.
  request "service-role" {
    operation = "update"
    path      = "pki/roles/vaultgate-service"
    data = {
      allowed_domains             = ["svc", "cluster.local", "localhost"]
      allow_subdomains            = true
      allow_bare_domains          = true
      allow_wildcard_certificates = false
      allow_ip_sans               = false
      enforce_hostnames           = true
      require_cn                  = false
      key_type                    = "ec"
      key_bits                    = 256
      server_flag                 = true
      client_flag                 = false
      ttl                         = "24h"
      max_ttl                     = "72h"
    }
  }
  # Client certificates for the API's internal port (M10, ADR 0013): an identity as a
  # URI in VaultGate's own namespace, spiffe://vaultgate/ns/vaultgate/sa/<account>, and
  # nothing else: no DNS names, IP addresses or localhost, and not usable by a server.
  request "client-role" {
    operation = "update"
    path      = "pki/roles/vaultgate-client"
    data = {
      allowed_domains   = []
      allow_localhost   = false
      allow_ip_sans     = false
      allowed_uri_sans  = ["spiffe://vaultgate/ns/vaultgate/sa/*"]
      enforce_hostnames = true
      require_cn        = false
      key_type          = "ec"
      key_bits          = 256
      server_flag       = false
      client_flag       = true
      ttl               = "24h"
      max_ttl           = "72h"
    }
  }
  # The nodes' CA (M11, ADR 0014): its own mount, so its own issuer, revocation lists,
  # OCSP and policies; its key never leaves OpenBao either.
  request "nodes-mount" {
    operation = "update"
    path      = "sys/mounts/pki-nodes"
    data = {
      type        = "pki"
      description = "The nodes' intermediate CA, signed by the offline root"
      config      = { max_lease_ttl = "2160h" }
    }
  }
  # Nodes are outside the cluster: their certificates point at VaultGate's public API,
  # which serves these from OpenBao (/pki/nodes/...). The local cluster's API is on
  # localhost:8000; elsewhere, VaultGate's public address.
  request "nodes-urls" {
    operation = "update"
    path      = "pki-nodes/config/urls"
    data = {
      issuing_certificates    = ["https://localhost:8000/pki/nodes/ca"]
      crl_distribution_points = ["https://localhost:8000/pki/nodes/crl"]
      ocsp_servers            = ["https://localhost:8000/pki/nodes/ocsp"]
    }
  }
  # Revocation: OCSP answers from the revocations as they are, at once. The full list is
  # rebuilt on a schedule (valid two days, rebuilt half a day before it expires), and a
  # delta list carries the revocations since, rebuilt every 5 minutes.
  request "nodes-crl" {
    operation = "update"
    path      = "pki-nodes/config/crl"
    data = {
      expiry                    = "48h"
      auto_rebuild              = true
      auto_rebuild_grace_period = "12h"
      enable_delta              = true
      delta_rebuild_interval    = "5m"
      ocsp_disable              = false
    }
  }
  # Node certificates: a node's identity as a URI, spiffe://nodes.vaultgate/node/<id>,
  # and nothing else; for clients only; ECDSA P-256; a day by default, a week at most.
  # The identity comes from the signer, never from the CSR: whatever names a CSR asks
  # for are ignored (use_csr_sans, use_csr_common_name), so a node chooses its key and
  # nothing else.
  request "node-role" {
    operation = "update"
    path      = "pki-nodes/roles/node"
    data = {
      allowed_domains     = []
      allow_localhost     = false
      allow_ip_sans       = false
      allowed_uri_sans    = ["spiffe://nodes.vaultgate/node/*"]
      enforce_hostnames   = true
      require_cn          = false
      use_csr_sans        = false
      use_csr_common_name = false
      key_type            = "ec"
      key_bits            = 256
      server_flag         = false
      client_flag         = true
      ttl                 = "24h"
      max_ttl             = "168h"
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
path "pki-nodes/intermediate/generate/internal" { capabilities = ["update"] }
path "pki-nodes/intermediate/set-signed" { capabilities = ["update"] }
path "pki-nodes/issuers" { capabilities = ["list"] }
path "pki-nodes/issuer/+" { capabilities = ["read"] }
path "pki-nodes/config/issuers" { capabilities = ["update"] }
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
  # `make k3d-check`'s login for the nodes' CA (scripts/pki.py check-nodes): it signs a
  # short-lived certificate under the node role, sees it verify and then fail once
  # revoked, through the API's OCSP. The local cluster only; the enrollment API is what
  # signs nodes' certificates.
  request "nodes-check-policy" {
    operation = "update"
    path      = "sys/policies/acl/pki-nodes-check"
    data = {
      policy = <<EOT
path "pki-nodes/sign/node" { capabilities = ["update"] }
path "pki-nodes/revoke" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
EOT
    }
  }
  request "nodes-check-role" {
    operation = "update"
    path      = "auth/kubernetes/role/pki-nodes-check"
    data = {
      bound_service_account_names      = ["pki-nodes-check"]
      bound_service_account_namespaces = ["openbao"]
      audience                         = "openbao"
      token_policies                   = ["pki-nodes-check"]
      token_ttl                        = "10m"
      token_max_ttl                    = "10m"
      token_no_default_policy          = true
    }
  }
  request "cert-manager-policy" {
    operation = "update"
    path      = "sys/policies/acl/cert-manager"
    data = {
      policy = <<EOT
path "pki/sign/vaultgate-service" { capabilities = ["update"] }
EOT
    }
  }
  # cert-manager asks for this service account's token with its issuer's audience
  # (vault://<ClusterIssuer name>), so the token is good for this issuer only.
  request "cert-manager-role" {
    operation = "update"
    path      = "auth/kubernetes/role/cert-manager"
    data = {
      bound_service_account_names      = ["openbao-issuer"]
      bound_service_account_namespaces = ["cert-manager"]
      audience                         = "vault://vaultgate-ca"
      token_policies                   = ["cert-manager"]
      token_ttl                        = "10m"
      token_max_ttl                    = "10m"
    }
  }
  # The client certificates' issuer: a namespaced Issuer in VaultGate's namespace, which
  # logs in as that namespace's vaultgate-client-issuer account, with its own audience
  # (vault://<namespace>/<issuer>), and may sign under the client role only.
  request "cert-manager-clients-policy" {
    operation = "update"
    path      = "sys/policies/acl/cert-manager-clients"
    data = {
      policy = <<EOT
path "pki/sign/vaultgate-client" { capabilities = ["update"] }
EOT
    }
  }
  request "cert-manager-clients-role" {
    operation = "update"
    path      = "auth/kubernetes/role/cert-manager-clients"
    data = {
      bound_service_account_names      = ["vaultgate-client-issuer"]
      bound_service_account_namespaces = ["vaultgate"]
      audience                         = "vault://vaultgate/vaultgate-clients"
      token_policies                   = ["cert-manager-clients"]
      token_ttl                        = "10m"
      token_max_ttl                    = "10m"
    }
  }
}

# The services' credentials (M9, ADR 0012), in a key-value store: each secret at
# secret/vaultgate/<name>, its value in the field `value`. Each service logs in as its
# own service account and may read the secrets it uses and nothing else; the values
# never pass through git or Helm values. `make k3d-up` seeds them with random values
# (scripts/service_secrets.py seed), and each service's own AWS key (aws-api,
# aws-gateway, aws-scanner; M10, TM-2) from Terraform's per-service IAM users
# (scripts/service_secrets.py seed-aws), as the secrets-seed service account. That
# account may create a secret and see whether one exists (its metadata), but not read or
# change one: a seeded value is never overwritten. It also rotates OpenBao's own database
# password once PostgreSQL is up, after which nobody but OpenBao knows it.
initialize "secrets" {
  request "mount" {
    operation = "update"
    path      = "sys/mounts/secret"
    data = {
      type        = "kv"
      description = "VaultGate's service credentials"
      options     = { version = "2" }
    }
  }
  request "seed-policy" {
    operation = "update"
    path      = "sys/policies/acl/secrets-seed"
    data = {
      policy = <<EOT
path "secret/data/vaultgate/*" { capabilities = ["create"] }
path "secret/metadata/vaultgate/*" { capabilities = ["read"] }
path "database/rotate-root/vaultgate" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
EOT
    }
  }
  request "seed-role" {
    operation = "update"
    path      = "auth/kubernetes/role/secrets-seed"
    data = {
      bound_service_account_names      = ["secrets-seed"]
      bound_service_account_namespaces = ["openbao"]
      audience                         = "openbao"
      token_policies                   = ["secrets-seed"]
      token_ttl                        = "10m"
      token_max_ttl                    = "10m"
      token_no_default_policy          = true
    }
  }
  request "api-policy" {
    operation = "update"
    path      = "sys/policies/acl/vaultgate-api"
    data = {
      policy = <<EOT
path "database/creds/vaultgate-api" { capabilities = ["read"] }
path "secret/data/vaultgate/internal-token" { capabilities = ["read"] }
path "secret/data/vaultgate/scanner-token" { capabilities = ["read"] }
path "secret/data/vaultgate/aws-api" { capabilities = ["read"] }
EOT
    }
  }
  request "gateway-policy" {
    operation = "update"
    path      = "sys/policies/acl/vaultgate-gateway"
    data = {
      policy = <<EOT
path "secret/data/vaultgate/internal-token" { capabilities = ["read"] }
path "secret/data/vaultgate/aws-gateway" { capabilities = ["read"] }
EOT
    }
  }
  request "scanner-policy" {
    operation = "update"
    path      = "sys/policies/acl/vaultgate-scanner"
    data = {
      policy = <<EOT
path "secret/data/vaultgate/scanner-token" { capabilities = ["read"] }
path "secret/data/vaultgate/aws-scanner" { capabilities = ["read"] }
EOT
    }
  }
  # One login per service: its service account in the vaultgate namespace, a token for
  # OpenBao's audience, and a short-lived OpenBao token with that service's policy.
  request "api-role" {
    operation = "update"
    path      = "auth/kubernetes/role/vaultgate-api"
    data = {
      bound_service_account_names      = ["vaultgate-api"]
      bound_service_account_namespaces = ["vaultgate"]
      audience                         = "openbao"
      token_policies                   = ["vaultgate-api"]
      token_ttl                        = "10m"
      token_max_ttl                    = "1h"
    }
  }
  request "gateway-role" {
    operation = "update"
    path      = "auth/kubernetes/role/vaultgate-gateway"
    data = {
      bound_service_account_names      = ["vaultgate-gateway"]
      bound_service_account_namespaces = ["vaultgate"]
      audience                         = "openbao"
      token_policies                   = ["vaultgate-gateway"]
      token_ttl                        = "10m"
      token_max_ttl                    = "1h"
    }
  }
  request "scanner-role" {
    operation = "update"
    path      = "auth/kubernetes/role/vaultgate-scanner"
    data = {
      bound_service_account_names      = ["vaultgate-scanner"]
      bound_service_account_namespaces = ["vaultgate"]
      audience                         = "openbao"
      token_policies                   = ["vaultgate-scanner"]
      token_ttl                        = "10m"
      token_max_ttl                    = "1h"
    }
  }
}

# The API's database credentials (M9, ADR 0012): short-lived, one set per pod, from the
# database engine. Each is a PostgreSQL login that acts as vaultgate_owner (the schema's
# owner, which nobody logs in as) and owns nothing itself: when its lease ends OpenBao
# ends its sessions and drops it. OpenBao logs in as `openbao`, over TLS verified with
# the cluster's trust bundle; its first password comes from the environment (a Secret
# `make k3d-up` creates) and is rotated right after, so only OpenBao knows it. The
# connection is not checked here: PostgreSQL may not be up yet.
initialize "database" {
  request "mount" {
    operation = "update"
    path      = "sys/mounts/database"
    data      = { type = "database" }
  }
  request "connection" {
    operation = "update"
    path      = "database/config/vaultgate"
    data = {
      plugin_name       = "postgresql-database-plugin"
      connection_url    = "postgresql://{{username}}:{{password}}@postgres.vaultgate-deps.svc:5432/vaultgate?sslmode=verify-full&sslrootcert=/openbao/trust/ca-certificates.crt"
      username          = "openbao"
      password          = { eval_type = "string", eval_source = "env", env_var = "OPENBAO_POSTGRES_PASSWORD", require_present = true }
      verify_connection = false
      allowed_roles     = ["vaultgate-api"]
    }
  }
  request "api-role" {
    operation = "update"
    path      = "database/roles/vaultgate-api"
    data = {
      db_name = "vaultgate"
      creation_statements = [
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE vaultgate_owner;",
        "ALTER ROLE \"{{name}}\" SET role = 'vaultgate_owner';",
      ]
      revocation_statements = [
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';",
        "DROP ROLE IF EXISTS \"{{name}}\";",
      ]
      default_ttl = "1h"
      max_ttl     = "24h"
    }
  }
}
