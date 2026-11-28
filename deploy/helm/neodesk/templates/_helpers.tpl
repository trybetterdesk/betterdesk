{{- define "neodesk.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "neodesk.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "neodesk.labels" -}}
app.kubernetes.io/name: {{ include "neodesk.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "neodesk.selector" -}}
app.kubernetes.io/name: {{ include "neodesk.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{- define "neodesk.secretName" -}}
{{- default (printf "%s-secrets" (include "neodesk.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "neodesk.claimName" -}}
{{- default (printf "%s-data" (include "neodesk.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{- define "neodesk.valkeyURL" -}}
{{- if .Values.valkey.url -}}
{{- .Values.valkey.url -}}
{{- else if .Values.valkey.enabled -}}
{{- printf "redis://%s-valkey:6379/0" (include "neodesk.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* The chart refuses settings several replicas can't run with (the
server refuses them too, at its start). */}}
{{- define "neodesk.validate" -}}
{{- if not .Values.publicHost -}}
{{- fail "publicHost is required: the address clients reach the server at" -}}
{{- end -}}
{{- $several := or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled -}}
{{- if $several -}}
{{- if and (not .Values.postgresql.url) (not .Values.secrets.existingSecret) -}}
{{- fail "several replicas need PostgreSQL: set postgresql.url or DATABASE_URL in secrets.existingSecret" -}}
{{- end -}}
{{- if and (not (include "neodesk.valkeyURL" .)) (not .Values.secrets.existingSecret) -}}
{{- fail "several replicas need Valkey: set valkey.url, VALKEY_URL in secrets.existingSecret, or valkey.enabled for a test" -}}
{{- end -}}
{{- if and (eq .Values.persistence.accessMode "ReadWriteOnce") (not .Values.persistence.existingClaim) -}}
{{- fail "several replicas share one volume: set persistence.accessMode to ReadWriteMany" -}}
{{- end -}}
{{- end -}}
{{- end -}}
