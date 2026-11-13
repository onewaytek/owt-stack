{{/* The app's name, required (values.schema.json also refuses an empty one). */}}
{{- define "owt.name" -}}
{{- required "name is required" .Values.name -}}
{{- end -}}

{{/* The namespace every object goes in: `namespace`, or the one Argo renders into. */}}
{{- define "owt.namespace" -}}
{{- .Values.namespace | default .Release.Namespace -}}
{{- end -}}

{{/* The database cluster's name: <name>-<suffix>. */}}
{{- define "owt.db" -}}
{{- include "owt.name" . }}-{{ .Values.database.suffix -}}
{{- end -}}

{{/*
The runtime role's name before _runtime: `database.rolePrefix`, or the name with each
hyphen as an underscore (my-app serves as my_app_runtime). Postgres takes a hyphen
only quoted, so anything but a-z, 0-9 and _ fails the render.
*/}}
{{- define "owt.rolePrefix" -}}
{{- $p := .Values.database.rolePrefix | default (include "owt.name" . | replace "-" "_") -}}
{{- if not (regexMatch "^[a-z_][a-z0-9_]*$" $p) -}}
{{- fail (printf "database.rolePrefix %q is not a role name (a-z, 0-9 and _, not starting with a digit)" $p) -}}
{{- end -}}
{{- $p -}}
{{- end -}}

{{/* The pinned image: <repository>@<digest>. */}}
{{- define "owt.image" -}}
{{- required "image.repository is required" .Values.image.repository }}@{{ required "image.digest is required" .Values.image.digest -}}
{{- end -}}

{{/* The tunnel is rendered when both its host and its id are set, refused with one alone. */}}
{{- define "owt.tunnel" -}}
{{- if or .Values.tunnel.host .Values.tunnel.id -}}
{{- if not (and .Values.tunnel.host .Values.tunnel.id) -}}
{{- fail "tunnel.host and tunnel.id go together (the public host, and the UUID of the tunnel that serves it)" -}}
{{- end -}}
true
{{- end -}}
{{- end -}}

{{/* The tunnel's credentials Secret: tunnel.credentialsSecret, or <name>-tunnel. */}}
{{- define "owt.tunnelSecret" -}}
{{- .Values.tunnel.credentialsSecret | default (printf "%s-tunnel" (include "owt.name" .)) -}}
{{- end -}}

{{/*
cloudflared's config as the ConfigMap holds it. tunnel.yaml renders it, and its
checksum (the first 16 hex digits of the SHA-256 of the config without its final
newline) goes in the connectors' pod template, so a change to it rolls them.
*/}}
{{- define "owt.tunnelConfig" -}}
tunnel: {{ .Values.tunnel.id }}
credentials-file: /etc/cloudflared/creds/credentials.json
# The image is pinned, and a self-update would drop every connection.
no-autoupdate: true
# Serves /ready, which the probes read: 200 only once this connector has
# registered with the edge.
metrics: 0.0.0.0:2000
ingress:
  # app.yaml's Service, on its port 80. cloudflared upgrades WebSockets and
  # streams SSE, and does not time out a response in flight. No
  # originRequest.httpHostHeader: the browser's Host passes through, so the
  # app sees TUNNEL_HOST, which its origin checks compare against.
  - hostname: "{{ .Values.tunnel.host }}"
    service: http://{{ include "owt.name" . }}:80
  # Required: cloudflared refuses to start without a catch-all last rule.
  - service: http_status:404
{{ end -}}

{{/* The annotation that keeps Argo from pruning or deleting a stateful object. */}}
{{- define "owt.keep" -}}
argocd.argoproj.io/sync-options: Prune=false,Delete=false
{{- end -}}

{{/* The envFrom every container of the app reads: <name>-env, then the settings. */}}
{{- define "owt.settingsRef" -}}
{{- if .Values.settings.configMap }}
- configMapRef: {name: "{{ include "owt.name" . }}-settings"}
{{- end }}
{{- end -}}

{{/* The pod-template security context every container of the app runs with. */}}
{{- define "owt.securityContext" -}}
runAsNonRoot: true
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
seccompProfile: {type: RuntimeDefault}
{{- end -}}
