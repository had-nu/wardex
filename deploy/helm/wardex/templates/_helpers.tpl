{{/*
Expand the name of the chart.
*/}}
{{- define "wardex.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncated to 63 chars to respect DNS label limits.
*/}}
{{- define "wardex.fullname" -}}
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
Chart label value: <name>-<version>
*/}}
{{- define "wardex.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "wardex.labels" -}}
helm.sh/chart: {{ include "wardex.chart" . }}
{{ include "wardex.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: wardex
{{- end }}

{{/*
Selector labels (stable — used in matchLabels; never change after initial install).
*/}}
{{- define "wardex.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wardex.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "wardex.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "wardex.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference: repository:tag (tag defaults to appVersion).
*/}}
{{- define "wardex.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/*
Name of the accept Secret.
*/}}
{{- define "wardex.secretName" -}}
{{- if .Values.acceptSecret.name }}
{{- .Values.acceptSecret.name }}
{{- else }}
{{- printf "%s-accept-secret" (include "wardex.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Name of the config ConfigMap.
*/}}
{{- define "wardex.configMapName" -}}
{{- printf "%s-config" (include "wardex.fullname" .) }}
{{- end }}

{{/*
Name of the frameworks ConfigMap.
*/}}
{{- define "wardex.frameworksConfigMapName" -}}
{{- printf "%s-frameworks" (include "wardex.fullname" .) }}
{{- end }}

{{/*
Name of the data PVC.
*/}}
{{- define "wardex.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- printf "%s-data" (include "wardex.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Framework controls path — positional arg to wardex evaluate.
*/}}
{{- define "wardex.frameworkPath" -}}
{{- printf "/frameworks/%s/" .Values.framework }}
{{- end }}

{{/*
Shared pod spec fragment used by both Job and CronJob.
Rendered as a named template and called with the top-level context.
*/}}
{{- define "wardex.podSpec" -}}
serviceAccountName: {{ include "wardex.serviceAccountName" . }}
automountServiceAccountToken: false
restartPolicy: {{ .Values.job.restartPolicy }}
{{- with .Values.podSecurityContext }}
securityContext:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.image.pullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
initContainers:
  {{- if .Values.kev.enabled }}
  - name: kev-fetch
    image: {{ printf "%s:%s" .Values.kev.image.repository .Values.kev.image.tag }}
    imagePullPolicy: {{ .Values.kev.image.pullPolicy }}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 65532
      capabilities:
        drop:
          - ALL
    command:
      - sh
      - -c
      - |
        curl -sSL --fail --retry 3 --retry-delay 5 \
          {{ .Values.kev.url | quote }} \
          -o {{ .Values.kev.path | quote }}
        echo "[kev-fetch] KEV catalogue downloaded to {{ .Values.kev.path }}"
    volumeMounts:
      - name: tmp
        mountPath: /tmp
  {{- end }}
  {{- if eq .Values.evidence.source "grype" }}
  - name: grype-convert
    image: {{ include "wardex.image" . }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    securityContext:
      {{- toYaml .Values.containerSecurityContext | nindent 6 }}
    command:
      - /wardex
      - convert
      - grype
      - /grype/{{ .Values.evidence.grypeSubPath }}
      {{- if .Values.kev.enabled }}
      - --kev
      - {{ .Values.kev.path }}
      {{- end }}
      - --output
      - /evidence/wardex-vulns.yaml
    env:
      {{- include "wardex.commonEnv" . | nindent 6 }}
    volumeMounts:
      - name: tmp
        mountPath: /tmp
      - name: grype-input
        mountPath: /grype
        readOnly: true
      - name: evidence
        mountPath: /evidence
  {{- end }}
containers:
  - name: wardex
    image: {{ include "wardex.image" . }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    {{- with .Values.containerSecurityContext }}
    securityContext:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    command:
      - /wardex
      - evaluate
      - --config
      - /etc/wardex/wardex-config.yaml
      - --evidence
      - /evidence/wardex-vulns.yaml
      - --gate-log
      - /data/wardex-gate-audit.log
      - --art14-output-dir
      - /data/art14
      {{- if .Values.kev.enabled }}
      - --kev
      - {{ .Values.kev.path }}
      {{- end }}
      - {{ include "wardex.frameworkPath" . }}
      {{- range .Values.job.extraArgs }}
      - {{ . | quote }}
      {{- end }}
    env:
      {{- include "wardex.commonEnv" . | nindent 6 }}
    {{- with .Values.job.resources }}
    resources:
      {{- toYaml . | nindent 6 }}
    {{- end }}
    volumeMounts:
      - name: config
        mountPath: /etc/wardex
        readOnly: true
      - name: frameworks
        mountPath: /frameworks/{{ .Values.framework }}
        readOnly: true
      - name: evidence
        mountPath: /evidence
        readOnly: true
      - name: data
        mountPath: /data
      - name: tmp
        mountPath: /tmp
      {{- range .Values.extraVolumeMounts }}
      - {{- toYaml . | nindent 8 }}
      {{- end }}
volumes:
  - name: config
    configMap:
      name: {{ include "wardex.configMapName" . }}
  - name: frameworks
    configMap:
      name: {{ include "wardex.frameworksConfigMapName" . }}
  - name: evidence
    {{- if eq .Values.evidence.source "configmap" }}
    configMap:
      name: {{ printf "%s-evidence" (include "wardex.fullname" .) }}
    {{- else if eq .Values.evidence.source "pvc" }}
    persistentVolumeClaim:
      claimName: {{ required "evidence.pvcName is required when evidence.source is pvc" .Values.evidence.pvcName }}
      readOnly: true
    {{- else if eq .Values.evidence.source "grype" }}
    emptyDir: {}
    {{- end }}
  {{- if eq .Values.evidence.source "grype" }}
  - name: grype-input
    persistentVolumeClaim:
      claimName: {{ required "evidence.grypePvcName is required when evidence.source is grype" .Values.evidence.grypePvcName }}
      readOnly: true
  {{- end }}
  - name: data
    persistentVolumeClaim:
      claimName: {{ include "wardex.pvcName" . }}
  - name: tmp
    emptyDir: {}
  {{- range .Values.extraVolumes }}
  - {{- toYaml . | nindent 4 }}
  {{- end }}
{{- with .Values.job.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.job.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.job.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Common environment variables shared by all wardex containers.
*/}}
{{- define "wardex.commonEnv" -}}
- name: WARDEX_ACCEPT_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "wardex.secretName" . }}
      key: {{ .Values.acceptSecret.key }}
{{- range .Values.extraEnv }}
- {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}
