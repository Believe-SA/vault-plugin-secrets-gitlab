# Build the plugin binary, then run it inside an official Vault dev container.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/vault-plugin-secrets-gitlab .

FROM hashicorp/vault:latest
COPY --from=build /out/vault-plugin-secrets-gitlab /vault/plugins/vault-plugin-secrets-gitlab
ENV VAULT_LOCAL_CONFIG='{"plugin_directory":"/vault/plugins"}'
