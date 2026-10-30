{{- define "spinxsca.name" -}}{{ .Release.Name }}-spinxsca{{- end -}}
{{- define "spinxsca.labels" -}}
app.kubernetes.io/name: spinxsca
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
{{- define "spinxsca.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag }}{{- end -}}
