{{- define "thorax-kubernetes-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "thorax-kubernetes-controller.admissionPolicyName" -}}
{{- printf "%s-%s" (include "thorax-kubernetes-controller.fullname" .) (sha256sum .Release.Namespace | trunc 8) | trunc 63 | trimSuffix "-" -}}
{{- end }}

{{- define "thorax-kubernetes-controller.image" -}}
{{- if .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be a lowercase sha256 digest" -}}
{{- end -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else if .Values.image.allowMutableTag -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- else -}}
{{- fail "image.digest is required; set image.allowMutableTag=true only for disposable development" -}}
{{- end -}}
{{- end }}

{{- define "thorax-kubernetes-controller.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "thorax-kubernetes-controller.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "thorax-kubernetes-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "thorax-kubernetes-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "thorax-kubernetes-controller.labels" -}}
app.kubernetes.io/name: {{ include "thorax-kubernetes-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
