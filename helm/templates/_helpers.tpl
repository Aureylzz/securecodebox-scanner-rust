{{/*
This file contains helper templates that generate consistent names and labels
across all resources in our Helm chart. Think of these as reusable functions.
*/}}

{{/*
Expand the name of the chart.
This is used as a base for resource names.
*/}}
{{- define "rust-scan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
This combines the release name with the chart name to ensure uniqueness.
For example: if we install with 'helm install my-scanner ./helm'
this would generate names like 'my-scanner-rust-scan'
*/}}
{{- define "rust-scan.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
This helps track which version of the chart created each resource.
*/}}
{{- define "rust-scan.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels that should be applied to all resources.
These labels help with resource selection and management.
*/}}
{{- define "rust-scan.labels" -}}
helm.sh/chart: {{ include "rust-scan.chart" . }}
{{ include "rust-scan.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels are used to identify resources belonging to this application.
These are a subset of the common labels used for pod selection.
*/}}
{{- define "rust-scan.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rust-scan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}