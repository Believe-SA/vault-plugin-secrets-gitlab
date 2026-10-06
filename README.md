# vault-plugin-secrets-gitlab

[![CI](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/ci.yml/badge.svg)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/ci.yml)
[![Release](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/release.yml/badge.svg)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/release.yml)
[![Latest release](https://img.shields.io/github/v/release/Believe-SA/vault-plugin-secrets-gitlab?sort=semver&logo=github)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/releases/latest)
[![Go version](https://img.shields.io/github/go-mod/go-version/Believe-SA/vault-plugin-secrets-gitlab?logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Vault compatibility** — the compiled plugin is registered, mounted and exercised inside a real Vault server in CI:

| Vault | Status |
|---|---|
| 2.1.x | [![](https://img.shields.io/github/actions/workflow/status/Believe-SA/vault-plugin-secrets-gitlab/ci.yml?job=Vault+2.1.1&label=2.1.1)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/ci.yml) |
| 2.0.x | [![](https://img.shields.io/github/actions/workflow/status/Believe-SA/vault-plugin-secrets-gitlab/ci.yml?job=Vault+2.0.4&label=2.0.4)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/ci.yml) |
| 1.21.x | [![](https://img.shields.io/github/actions/workflow/status/Believe-SA/vault-plugin-secrets-gitlab/ci.yml?job=Vault+1.21.4&label=1.21.4)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/ci.yml) |
| latest GA | [![](https://img.shields.io/github/actions/workflow/status/Believe-SA/vault-plugin-secrets-gitlab/ci.yml?job=Vault+latest&label=latest)](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/actions/workflows/ci.yml) |

**Platforms** — cross-compiled in CI and published on every release: linux, darwin, freebsd, openbsd, windows × amd64, arm64.

A Vault secrets engine that issues [GitLab project access tokens][pat] on demand:

- Tokens are minted through the GitLab API from a single parent token held by Vault
- Free-form requests (`token`, `dynamic/project_id/<id>/name/<name>`) or predefined **roles** (`token/<role>`)
- Scopes, access level (guest → maintainer, owner opt-in) and expiry, bounded by a mount-wide `max_ttl`
- Access gated by standard Vault ACLs
- Multiplexed, versioned plugin: register it in the catalog with `-version` and pin mounts to a release

Forked from [splunk/vault-plugin-secrets-gitlab](https://github.com/splunk/vault-plugin-secrets-gitlab) and kept in sync with upstream.

## Requirements

- GitLab **14.1** or later (project access tokens with access level)
- Self-managed instances on Free and above, or GitLab SaaS Premium and above
- A parent token of a user with Maintainer (or higher) permission on the target projects
- Ideally, lift the API rate limit for that user — see [allow specific users to bypass authenticated request rate limiting][lift rate limit]

## Install (pre-built binary)

1. Download the asset matching your Vault server from the
   [latest release](https://github.com/Believe-SA/vault-plugin-secrets-gitlab/releases/latest),
   e.g. `vault-plugin-secrets-gitlab_<version>_linux_amd64`, together with
   `checksums.txt`.

2. Verify and install it into Vault's `plugin_directory` under the plugin's
   command name:

   ```bash
   sha256sum --ignore-missing -c checksums.txt
   install -m 0755 vault-plugin-secrets-gitlab_<version>_linux_amd64 \
     /etc/vault/plugins/vault-plugin-secrets-gitlab
   ```

3. Register the plugin and enable the secrets engine:

   ```bash
   SHASUM=$(sha256sum /etc/vault/plugins/vault-plugin-secrets-gitlab | cut -d ' ' -f1)
   vault plugin register -sha256="$SHASUM" -version="v<version>" \
     secret vault-plugin-secrets-gitlab
   vault secrets enable -path=gitlab -plugin-version="v<version>" vault-plugin-secrets-gitlab
   ```

   `-version` is optional — without it Vault records the version the binary
   reports. When given, it **must** match the binary (`v` + the release
   version) or Vault refuses the registration. Pinning the version lets you
   upgrade mount by mount with `vault secrets tune -plugin-version=... gitlab/`
   followed by `vault plugin reload -mounts=gitlab/`.

Check a binary's build metadata at any time with
`vault-plugin-secrets-gitlab --version`.

### Setup

Configure the mount with the parent token used to mint project access tokens:

```text
$ vault write gitlab/config \
    base_url="https://gitlab.example.com" \
    token="$GITLAB_TOKEN" \
    max_ttl=720h
Key                  Value
---                  -----
allow_owner_level    false
base_url             https://gitlab.example.com
max_ttl              2592000
```

| Field | Default | Description |
|---|---|---|
| `base_url` | `https://gitlab.com` | GitLab instance URL |
| `token` | — | Parent token; write-only, never returned |
| `max_ttl` | `0` (unbounded) | Upper bound for any requested `expires_at`; values below 24h are ignored |
| `allow_owner_level` | `false` | Allow `access_level=50` (Owner) |

Changes take effect immediately on the next request.

### Usage

Free-form request:

```text
$ vault write gitlab/token id=1 name=ci-token scopes=api,write_repository access_level=30 expires_at=2026-12-31T00:00:00Z
Key             Value
---             -----
access_level    30
expires_at      2026-12-31 00:00:00 +0000 UTC
id              12345
name            ci-token
scopes          [api write_repository]
token           glpat-REDACTED
```

The project and token name can also be carried by the path, which makes it
easy to scope ACL policies per project:

```text
$ vault write gitlab/dynamic/project_id/1/name/ci-token scopes=read_api
```

```hcl
# only project 1, any token name
path "gitlab/dynamic/project_id/1/name/*" {
  capabilities = ["create", "update"]
}
```

Roles predefine the parameters, so callers cannot choose them:

```text
$ vault write gitlab/roles/ci-role id=1 name=project1-role scopes=read_api,read_repository token_ttl=48h
$ vault write -f gitlab/token/ci-role
Key             Value
---             -----
access_level    40
expires_at      2026-10-08 00:00:00 +0000 UTC
id              12346
name            project1-role
scopes          [read_api read_repository]
token           glpat-REDACTED
```

See `vault path-help gitlab/` for every endpoint, and the
[design principles](docs/design-principles.md) for access-control guidance.

> GitLab project access tokens have day granularity (they expire at midnight
> UTC), so the shortest effective lifetime is about one day.

## Local Development

### Build and run in Docker

```bash
docker build -t vault-plugin-gitlab .
docker run --rm -d --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=root' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' -p 8200:8200 vault-plugin-gitlab

export VAULT_ADDR='http://127.0.0.1:8200'
vault login root

# Hash the binary *inside* the container — that is the file Vault checks.
CID=$(docker ps -q --filter ancestor=vault-plugin-gitlab | head -1)
SHASUM=$(docker exec "$CID" sha256sum /vault/plugins/vault-plugin-secrets-gitlab | cut -d ' ' -f1)
vault plugin register -sha256="$SHASUM" secret vault-plugin-secrets-gitlab
vault secrets enable -path=gitlab vault-plugin-secrets-gitlab
vault write gitlab/config base_url="$GITLAB_URL" token="$GITLAB_TOKEN"
```

### Build and run with a local Vault

```bash
# builds into ./plugins and starts `vault server -dev -dev-plugin-dir=./plugins`
make vault-only

# in another terminal
export VAULT_ADDR=http://127.0.0.1:8200 GITLAB_URL=https://gitlab.example.com GITLAB_TOKEN=...
./scripts/setup_dev_vault.sh
```

### Tests

Unit tests run with no external dependencies:

```bash
make test                          # all unit tests, with coverage in coverage/unit
make test TESTARGS='-run=TestConfig'
make report                        # coverage/coverage.html
```

Vault integration tests build the plugin, start a real `vault server -dev`,
register it in the catalog (sha256 + version), mount it, and drive every
endpoint against a fake GitLab API — including version pinning, multiplexed
mounts and plugin reload. The Vault binary is downloaded into `.tools/`:

```bash
make test-vault                        # latest GA Vault
make test-vault VAULT_VERSION=2.0.4    # a specific release
VAULT_BIN=$(which vault) go test ./integration -v   # your own binary
```

Acceptance tests mint real project access tokens against a live GitLab. `make
test-gitlab` starts a disposable GitLab CE container (`scripts/gitlab-ce.sh`,
about 5 minutes to boot, needs docker), creates an API token and a test
project, runs them and removes the container. To use an existing instance
instead:

```bash
export GITLAB_URL=https://gitlab.example.com
export GITLAB_TOKEN=<parent token>
export GITLAB_PROJECT_ID=<project id>
go test ./plugin -run TestAcc -v
```

In CI they run against GitLab CE **only as a release gate** (and on demand via
the "GitLab acceptance" workflow): no tag or release is published if they fail.

Lint with `make lint` (golangci-lint, config in `.golangci.yml`).

Known vulnerabilities are checked with
[govulncheck](https://go.dev/doc/security/vuln/) on every push, pull request
and weekly.

### Releases

Releases are automated. Every push to `main` is analyzed with
[Conventional Commits](https://www.conventionalcommits.org/): the next
[semver](https://semver.org/) is derived from the commit types since the last
tag, the live GitLab CE acceptance tests run, then the tag is created and
[GoReleaser](https://goreleaser.com) publishes the
cross-compiled binaries and `checksums.txt` to a GitHub Release. The release
version is stamped into the binary and reported to Vault as the plugin version.

| Commit prefix | Version bump |
| --- | --- |
| `fix:` | patch (`x.y.Z`) |
| `feat:` | minor (`x.Y.0`) |
| `feat!:` / `fix!:` / `BREAKING CHANGE:` footer | major (`X.0.0`) |
| `docs:`, `chore:`, `ci:`, `refactor:`, `test:`, `style:`, `build:` | no release |

You can also cut a release at any specific version by pushing a `v*` tag
directly (e.g. `git tag v1.0.0 && git push origin v1.0.0`) — that builds and
publishes that exact tag (after the same acceptance gate). Build every artifact locally without publishing with
`make release-snapshot`.

### Syncing with upstream

```bash
git remote add upstream https://github.com/splunk/vault-plugin-secrets-gitlab.git
git fetch upstream && git merge upstream/main
```

The Go module path is kept as `github.com/splunk/vault-plugin-secrets-gitlab`
to keep upstream merges conflict-free.

## Contribution

This plugin was initially created as a Hackathon project to enhance the ephemeral credential suite. Another example is [vault-plugin-secrets-artifactory]. Contributions in the form of issues and pull requests are welcome.

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## License

[Apache Software License version 2.0](LICENSE)

[pat]: https://docs.gitlab.com/user/project/settings/project_access_tokens/
[lift rate limit]: https://docs.gitlab.com/administration/settings/user_and_ip_rate_limits/#allow-specific-users-to-bypass-authenticated-request-rate-limiting
[vault-plugin-secrets-artifactory]: https://github.com/splunk/vault-plugin-secrets-artifactory
