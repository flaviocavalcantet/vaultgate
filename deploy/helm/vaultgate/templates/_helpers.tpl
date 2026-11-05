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

{{/* Settings every service reads: metrics port, traces, AWS. */}}
{{- define "vaultgate.commonEnv" -}}
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
