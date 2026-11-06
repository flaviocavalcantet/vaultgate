# OpenBao agent for the scanner (M9, ADR 0012), run as the pod's init container: it
# logs in as the pod's service account (vaultgate-scanner, a projected token for OpenBao's
# audience), writes the scanner's secrets as files to a memory-backed volume, and exits.
# OpenBao's address and CA come from BAO_ADDR and BAO_CACERT (the chart sets them).
# Until a secret exists the agent keeps trying, so the pod waits for `make k3d-up` to
# seed them (scripts/service_secrets.py).

exit_after_auth = true

auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      role       = "vaultgate-scanner"
      token_path = "/var/run/secrets/openbao/token"
    }
  }
}

template {
  destination = "/run/secrets/vaultgate/vaultgate_scanner_token"
  perms       = "0400"
  contents    = "{{ with secret \"secret/data/vaultgate/scanner-token\" }}{{ .Data.data.value }}{{ end }}"
}

template {
  destination = "/run/secrets/vaultgate/aws-credentials"
  perms       = "0400"
  contents    = "{{ with secret \"secret/data/vaultgate/aws\" }}{{ .Data.data.value }}{{ end }}"
}
