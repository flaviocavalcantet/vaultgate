{{/* Labels of one component (api, gateway, scanner). */}}
{{- define "vaultgate.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/part-of: vaultgate
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ .root.Chart.Name }}-{{ .root.Chart.Version }}
{{- end }}

{{/* What a component's Service and policies select it by. */}}
{{- define "vaultgate.selector" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end }}

{{- define "vaultgate.fullname" -}}
{{ .root.Release.Name }}-{{ .name }}
{{- end }}

{{- define "vaultgate.image" -}}
"{{ .root.Values.image.registry }}/vaultgate-{{ .name }}:{{ .root.Values.image.tag }}"
{{- end }}

{{/* Pod annotations: Prometheus discovery, and a checksum so a changed Secret the
chart owns restarts the pods that read it. */}}
{{- define "vaultgate.podAnnotations" -}}
{{- if .root.Values.metrics.podAnnotations }}
prometheus.io/scrape: "true"
prometheus.io/port: {{ .root.Values.metrics.port | quote }}
prometheus.io/path: /metrics
{{- if .root.Values.tls.enabled }}
prometheus.io/scheme: https
{{- end }}
{{- end }}
{{- if .root.Values.secrets.create }}
checksum/secret: {{ include (print .root.Template.BasePath "/secret.yaml") .root | sha256sum }}
{{- end }}
{{- end }}

{{/* One value from the credentials Secret. */}}
{{- define "vaultgate.secretEnv" -}}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ .root.Values.secrets.name }}
      key: {{ .key }}
      {{- if .optional }}
      optional: true
      {{- end }}
{{- end }}

{{/* http or https, as the services serve. */}}
{{- define "vaultgate.scheme" -}}
{{ ternary "https" "http" .Values.tls.enabled }}
{{- end }}

{{/* The API's internal port, by its Service's name in the namespace (a name its
certificate carries). */}}
{{- define "vaultgate.apiInternalUrl" -}}
{{ include "vaultgate.scheme" . }}://{{ .Release.Name }}-api.{{ .Release.Namespace }}.svc:{{ .Values.api.internalPort }}
{{- end }}

{{/* With TLS: the certificate a server presents (cert-manager's Secret). */}}
{{- define "vaultgate.tlsEnv" -}}
{{- if .root.Values.tls.enabled }}
- name: VAULTGATE_TLS_CERT_FILE
  value: /etc/vaultgate/tls/tls.crt
- name: VAULTGATE_TLS_KEY_FILE
  value: /etc/vaultgate/tls/tls.key
{{- end }}
{{- end }}

{{- define "vaultgate.tlsMount" -}}
{{- if .root.Values.tls.enabled }}
- { name: tls, mountPath: /etc/vaultgate/tls, readOnly: true }
{{- end }}
{{- end }}

{{- define "vaultgate.tlsVolume" -}}
{{- if .root.Values.tls.enabled }}
- name: tls
  secret: { secretName: {{ include "vaultgate.fullname" . }}-tls, defaultMode: 0440 }
{{- end }}
{{- end }}

{{/* With TLS: the trust bundle that replaces every service's trust store. */}}
{{- define "vaultgate.trustMount" -}}
{{- if .Values.tls.enabled }}
- { name: trust, mountPath: /etc/vaultgate/trust, readOnly: true }
{{- end }}
{{- end }}

{{- define "vaultgate.trustVolume" -}}
{{- if .Values.tls.enabled }}
- name: trust
  configMap: { name: {{ .Values.tls.trustBundle.configMap }} }
{{- end }}
{{- end }}

{{/* Settings every service reads: metrics port, traces, AWS, trust store. */}}
{{- define "vaultgate.commonEnv" -}}
{{- if .Values.tls.enabled }}
# What the services' clients trust (Python's ssl and Go's crypto/x509 both read it), and
# asyncpg for PostgreSQL (with ?ssl=verify-full in the database URL).
- name: SSL_CERT_FILE
  value: /etc/vaultgate/trust/{{ .Values.tls.trustBundle.key }}
- name: PGSSLROOTCERT
  value: /etc/vaultgate/trust/{{ .Values.tls.trustBundle.key }}
# The OTLP exporters (Python's and Go's) verify the trace collector with it.
- name: OTEL_EXPORTER_OTLP_CERTIFICATE
  value: /etc/vaultgate/trust/{{ .Values.tls.trustBundle.key }}
{{- end }}
- name: VAULTGATE_METRICS_PORT
  value: {{ .Values.metrics.port | quote }}
{{- with .Values.tracing.otlpEndpoint }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ . | quote }}
{{- end }}
- name: VAULTGATE_AWS_REGION
  value: {{ .Values.aws.region | quote }}
{{- with .Values.aws.endpointUrl }}
- name: VAULTGATE_AWS_ENDPOINT_URL
  value: {{ . | quote }}
{{- end }}
{{ include "vaultgate.secretEnv" (dict "root" . "env" "AWS_ACCESS_KEY_ID" "key" "aws-access-key-id" "optional" true) }}
{{ include "vaultgate.secretEnv" (dict "root" . "env" "AWS_SECRET_ACCESS_KEY" "key" "aws-secret-access-key" "optional" true) }}
{{- end }}

{{/* Extra NAME: value settings of one component. */}}
{{- define "vaultgate.extraEnv" -}}
{{- range $name, $value := . }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}

{{- define "vaultgate.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: ["ALL"] }
{{- end }}
