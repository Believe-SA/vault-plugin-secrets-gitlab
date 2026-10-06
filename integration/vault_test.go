// Copyright 2021 Splunk Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package integration runs the compiled plugin inside a real Vault server.
//
// The tests are skipped unless VAULT_BIN points at a Vault binary. They build
// the plugin, start `vault server -dev` with a plugin directory, register the
// plugin in the catalog (sha256 + semver version, as an operator would), mount
// it and drive every endpoint against a fake GitLab API.
//
//	VAULT_BIN=$(which vault) go test ./integration -v
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pluginName    = "vault-plugin-secrets-gitlab"
	pluginVersion = "v1.2.3"
	rootToken     = "root"
)

// fakeGitlab records project access token creations and answers like GitLab.
type fakeGitlab struct {
	*httptest.Server

	mu       sync.Mutex
	requests []fakeRequest
}

type fakeRequest struct {
	ProjectID string
	Token     string
	Body      map[string]any
}

var accessTokensPath = regexp.MustCompile(`^/api/v4/projects/([^/]+)/access_tokens$`)

func newFakeGitlab(t *testing.T) *fakeGitlab {
	t.Helper()

	f := &fakeGitlab{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := accessTokensPath.FindStringSubmatch(r.URL.Path)
		if r.Method != http.MethodPost || m == nil {
			http.NotFound(w, r)

			return
		}

		body := map[string]any{}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)

		f.mu.Lock()
		f.requests = append(f.requests, fakeRequest{ProjectID: m[1], Token: r.Header.Get("Private-Token"), Body: body})
		n := len(f.requests)
		f.mu.Unlock()

		accessLevel := body["access_level"]
		if accessLevel == nil {
			accessLevel = 40
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":           1000 + n,
			"name":         body["name"],
			"scopes":       body["scopes"],
			"expires_at":   body["expires_at"],
			"access_level": accessLevel,
			"active":       true,
			"token":        fmt.Sprintf("glpat-fake-%d", n),
		})
	}))
	t.Cleanup(f.Close)

	return f
}

func (f *fakeGitlab) last(t *testing.T) fakeRequest {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	require.NotEmpty(t, f.requests, "fake GitLab received no request")

	return f.requests[len(f.requests)-1]
}

func (f *fakeGitlab) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.requests)
}

// buildPlugin compiles the plugin with pluginVersion stamped in and returns
// the plugin directory and the binary sha256.
func buildPlugin(t *testing.T) (string, string) {
	t.Helper()

	dir, err := filepath.EvalSymlinks(t.TempDir()) // Vault rejects symlinked plugin dirs (macOS /var)
	require.NoError(t, err)

	bin := filepath.Join(dir, pluginName)
	cmd := exec.Command("go", "build", "-o", bin,
		"-ldflags", "-X github.com/splunk/vault-plugin-secrets-gitlab/plugin.Version="+pluginVersion,
		"..")

	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	content, err := os.ReadFile(bin)
	require.NoError(t, err)

	sum := sha256.Sum256(content)

	return dir, hex.EncodeToString(sum[:])
}

func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := l.Addr().String()
	require.NoError(t, l.Close())

	return addr
}

// startVault runs a dev server whose plugin_directory is pluginDir, without
// auto-registering anything so the test exercises the real catalog flow.
func startVault(t *testing.T, vaultBin, pluginDir string) *api.Client {
	t.Helper()

	cfg := filepath.Join(t.TempDir(), "vault.hcl")
	require.NoError(t, os.WriteFile(cfg, []byte(fmt.Sprintf("plugin_directory = %q\n", pluginDir)), 0o600))

	addr := freeAddr(t)
	logFile, err := os.Create(filepath.Join(t.TempDir(), "vault.log"))
	require.NoError(t, err)

	cmd := exec.Command(vaultBin, "server", "-dev",
		"-dev-root-token-id="+rootToken,
		"-dev-listen-address="+addr,
		"-config="+cfg,
		"-log-level=debug")

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	cmd.Env = append(os.Environ(), "VAULT_DISABLE_MLOCK=true", "SKIP_SETCAP=true")
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = logFile.Close()

		if t.Failed() {
			logs, _ := os.ReadFile(logFile.Name())
			t.Logf("vault server logs:\n%s", logs)
		}
	})

	conf := api.DefaultConfig()
	conf.Address = "http://" + addr
	client, err := api.NewClient(conf)
	require.NoError(t, err)
	client.SetToken(rootToken)

	require.Eventually(t, func() bool {
		h, err := client.Sys().Health()

		return err == nil && h.Initialized && !h.Sealed
	}, 30*time.Second, 200*time.Millisecond, "vault dev server did not become ready")

	return client
}

// loginAs logs in through an auth method and returns a client using that token.
func loginAs(t *testing.T, root *api.Client, path string, data map[string]any) *api.Client {
	t.Helper()

	secret, err := root.Logical().Write(path, data)
	require.NoError(t, err)

	c, err := root.Clone()
	require.NoError(t, err)
	c.SetToken(secret.Auth.ClientToken)

	return c
}

//nolint:funlen,maintidx
func TestVault(t *testing.T) {
	vaultBin := os.Getenv("VAULT_BIN")
	if vaultBin == "" {
		t.Skip("VAULT_BIN not set; skipping Vault integration tests")
	}

	out, err := exec.Command(vaultBin, "version").CombinedOutput()
	require.NoError(t, err, string(out))
	t.Logf("running against %s", strings.TrimSpace(string(out)))

	ctx := context.Background()
	pluginDir, sha := buildPlugin(t)
	client := startVault(t, vaultBin, pluginDir)
	sys := client.Sys()
	logical := client.Logical()
	gitlab := newFakeGitlab(t)
	other := newFakeGitlab(t)

	t.Run("binary reports its version", func(t *testing.T) {
		out, err := exec.Command(filepath.Join(pluginDir, pluginName), "--version").CombinedOutput()
		require.NoError(t, err, string(out))
		assert.Contains(t, string(out), pluginVersion)
	})

	t.Run("register and mount without explicit version", func(t *testing.T) {
		require.NoError(t, sys.RegisterPluginWithContext(ctx, &api.RegisterPluginInput{
			Name:    pluginName,
			Type:    api.PluginTypeSecrets,
			Command: pluginName,
			SHA256:  sha,
		}))
		require.NoError(t, sys.MountWithContext(ctx, "gitlab-unversioned", &api.MountInput{Type: pluginName}))

		m, err := sys.GetMountWithContext(ctx, "gitlab-unversioned")
		require.NoError(t, err)
		assert.Equal(t, pluginVersion, m.RunningVersion, "Vault should pick up the self-reported version")

		_, err = logical.Write("gitlab-unversioned/config", map[string]any{"base_url": gitlab.URL, "token": "t"})
		require.NoError(t, err)

		_, err = logical.Write("gitlab-unversioned/token", map[string]any{"id": 1, "name": "unversioned", "scopes": "api"})
		require.NoError(t, err)
	})

	t.Run("register versioned plugin in catalog", func(t *testing.T) {
		require.NoError(t, sys.RegisterPluginWithContext(ctx, &api.RegisterPluginInput{
			Name:    pluginName,
			Type:    api.PluginTypeSecrets,
			Command: pluginName,
			SHA256:  sha,
			Version: pluginVersion,
		}))

		p, err := sys.GetPluginWithContext(ctx, &api.GetPluginInput{
			Name:    pluginName,
			Type:    api.PluginTypeSecrets,
			Version: pluginVersion,
		})
		require.NoError(t, err)
		assert.Equal(t, pluginVersion, p.Version)
		assert.Equal(t, sha, p.SHA256)
	})

	t.Run("registering with a mismatched version is rejected", func(t *testing.T) {
		err := sys.RegisterPluginWithContext(ctx, &api.RegisterPluginInput{
			Name:    pluginName,
			Type:    api.PluginTypeSecrets,
			Command: pluginName,
			SHA256:  sha,
			Version: "v9.9.9",
		})
		require.Error(t, err, "Vault must refuse a version that differs from the plugin's RunningVersion")
		assert.Contains(t, err.Error(), "version mismatch")
	})

	t.Run("mount pinned to the registered version", func(t *testing.T) {
		require.NoError(t, sys.MountWithContext(ctx, "gitlab", &api.MountInput{
			Type:   pluginName,
			Config: api.MountConfigInput{PluginVersion: pluginVersion},
		}))

		m, err := sys.GetMountWithContext(ctx, "gitlab")
		require.NoError(t, err)
		assert.Equal(t, pluginVersion, m.RunningVersion)
		assert.Equal(t, sha, m.RunningSha256)
	})

	t.Run("config", func(t *testing.T) {
		resp, err := logical.Write("gitlab/config", map[string]any{
			"base_url": gitlab.URL,
			"token":    "parent-token",
			"max_ttl":  "168h",
		})
		require.NoError(t, err)
		assert.Equal(t, gitlab.URL, resp.Data["base_url"])
		assert.NotContains(t, resp.Data, "token", "parent token must never be returned")

		resp, err = logical.Read("gitlab/config")
		require.NoError(t, err)
		assert.Equal(t, gitlab.URL, resp.Data["base_url"])
		assert.Equal(t, json.Number("604800"), resp.Data["max_ttl"])
		assert.NotContains(t, resp.Data, "token")
	})

	t.Run("token via body", func(t *testing.T) {
		expires := time.Now().UTC().Add(48 * time.Hour)
		resp, err := logical.Write("gitlab/token", map[string]any{
			"id":           42,
			"name":         "ci-token",
			"scopes":       "read_api,read_repository",
			"access_level": 30,
			"expires_at":   expires.Format(time.RFC3339),
		})
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(resp.Data["token"].(string), "glpat-fake-"))
		assert.Equal(t, "ci-token", resp.Data["name"])
		assert.Equal(t, json.Number("30"), resp.Data["access_level"])

		req := gitlab.last(t)
		assert.Equal(t, "42", req.ProjectID)
		assert.Equal(t, "parent-token", req.Token)
		assert.Equal(t, "ci-token", req.Body["name"])
		assert.Equal(t, []any{"read_api", "read_repository"}, req.Body["scopes"])
		assert.InDelta(t, 30, req.Body["access_level"], 0)
		assert.Equal(t, expires.Format("2006-01-02"), req.Body["expires_at"])
	})

	t.Run("token via dynamic project_id/name path", func(t *testing.T) {
		resp, err := logical.Write("gitlab/dynamic/project_id/7/name/flat-token", map[string]any{
			"scopes": "read_api",
		})
		require.NoError(t, err)
		assert.Equal(t, "flat-token", resp.Data["name"])

		req := gitlab.last(t)
		assert.Equal(t, "7", req.ProjectID)
		assert.Equal(t, "flat-token", req.Body["name"])
		assert.NotContains(t, req.Body, "access_level", "unset access level must not be sent")
	})

	t.Run("token validation errors", func(t *testing.T) {
		before := gitlab.count()

		cases := map[string]map[string]any{
			"scopes are empty":              {"id": 1, "name": "x"},
			"invalid access level":          {"id": 1, "name": "x", "scopes": "api", "access_level": 25},
			"access level not permitted":    {"id": 1, "name": "x", "scopes": "api", "access_level": 50},
			"exceeds configured maximum tt": {"id": 1, "name": "x", "scopes": "api", "expires_at": strconv.FormatInt(time.Now().Add(30*24*time.Hour).Unix(), 10)},
		}
		for msg, data := range cases {
			_, err := logical.Write("gitlab/token", data)
			require.Error(t, err, msg)
			assert.Contains(t, err.Error(), msg)
		}

		assert.Equal(t, before, gitlab.count(), "invalid requests must not reach GitLab")
	})

	t.Run("roles", func(t *testing.T) {
		_, err := logical.Write("gitlab/roles/ci", map[string]any{
			"id":           99,
			"name":         "role-token",
			"scopes":       "read_repository",
			"access_level": 20,
			"token_ttl":    "48h",
		})
		require.NoError(t, err)

		resp, err := logical.Read("gitlab/roles/ci")
		require.NoError(t, err)
		assert.Equal(t, "role-token", resp.Data["name"])

		resp, err = logical.List("gitlab/roles")
		require.NoError(t, err)
		assert.Equal(t, []any{"ci"}, resp.Data["keys"])

		resp, err = logical.Write("gitlab/token/ci", nil)
		require.NoError(t, err)
		assert.Equal(t, "role-token", resp.Data["name"])
		assert.NotEmpty(t, resp.Data["expires_at"])

		req := gitlab.last(t)
		assert.Equal(t, "99", req.ProjectID)
		assert.InDelta(t, 20, req.Body["access_level"], 0)

		_, err = logical.Delete("gitlab/roles/ci")
		require.NoError(t, err)

		resp, err = logical.Read("gitlab/roles/ci")
		require.NoError(t, err)
		assert.Nil(t, resp)
	})

	t.Run("owner level requires allow_owner_level", func(t *testing.T) {
		_, err := logical.Write("gitlab/config", map[string]any{"allow_owner_level": true})
		require.NoError(t, err)

		resp, err := logical.Write("gitlab/token", map[string]any{
			"id": 1, "name": "owner", "scopes": "api", "access_level": 50,
		})
		require.NoError(t, err)
		assert.Equal(t, json.Number("50"), resp.Data["access_level"])
	})

	t.Run("reconfiguring base_url takes effect immediately", func(t *testing.T) {
		_, err := logical.Write("gitlab/config", map[string]any{"base_url": other.URL, "token": "rotated"})
		require.NoError(t, err)

		_, err = logical.Write("gitlab/token", map[string]any{"id": 3, "name": "after-rotate", "scopes": "api"})
		require.NoError(t, err)

		req := other.last(t)
		assert.Equal(t, "rotated", req.Token)
		assert.Equal(t, "after-rotate", req.Body["name"])
	})

	t.Run("multiplexed second mount is isolated", func(t *testing.T) {
		require.NoError(t, sys.MountWithContext(ctx, "gitlab-b", &api.MountInput{
			Type:   pluginName,
			Config: api.MountConfigInput{PluginVersion: pluginVersion},
		}))

		resp, err := logical.Read("gitlab-b/config")
		require.NoError(t, err)
		assert.Nil(t, resp, "second mount must not see the first mount's config")

		_, err = logical.Write("gitlab-b/token", map[string]any{"id": 1, "name": "x", "scopes": "api"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configuration has not been set up")
	})

	t.Run("plugin reload keeps mounts working", func(t *testing.T) {
		_, err := sys.ReloadPluginWithContext(ctx, &api.ReloadPluginInput{Plugin: pluginName})
		require.NoError(t, err)

		var lastErr error

		require.Eventually(t, func() bool {
			_, lastErr = logical.Write("gitlab/token", map[string]any{"id": 5, "name": "after-reload", "scopes": "api"})

			return lastErr == nil
		}, 15*time.Second, 250*time.Millisecond)

		if lastErr != nil {
			t.Logf("last error: %v", lastErr)
		}
	})

	t.Run("templated policy: entity metadata picks the project", func(t *testing.T) {
		require.NoError(t, sys.EnableAuthWithOptionsWithContext(ctx, "userpass", &api.EnableAuthOptions{Type: "userpass"}))
		require.NoError(t, sys.PutPolicyWithContext(ctx, "gitlab-own-project", `
path "gitlab/dynamic/project_id/{{identity.entity.metadata.gitlab_project_id}}/name/{{identity.entity.name}}" {
  capabilities = ["create", "update"]
}`))

		_, err := logical.Write("auth/userpass/users/alice", map[string]any{"password": "pw", "token_policies": "gitlab-own-project"})
		require.NoError(t, err)

		entity, err := logical.Write("identity/entity", map[string]any{
			"name":     "alice",
			"metadata": map[string]string{"gitlab_project_id": "21"},
		})
		require.NoError(t, err)

		auths, err := sys.ListAuthWithContext(ctx)
		require.NoError(t, err)

		_, err = logical.Write("identity/entity-alias", map[string]any{
			"name":           "alice",
			"canonical_id":   entity.Data["id"],
			"mount_accessor": auths["userpass/"].Accessor,
		})
		require.NoError(t, err)

		alice := loginAs(t, client, "auth/userpass/login/alice", map[string]any{"password": "pw"})

		_, err = alice.Logical().Write("gitlab/dynamic/project_id/21/name/alice", map[string]any{"scopes": "read_api", "ttl": "1h"})
		require.NoError(t, err, "own project, own name")

		for _, path := range []string{
			"gitlab/dynamic/project_id/22/name/alice", // other project
			"gitlab/dynamic/project_id/21/name/bob",   // other token name
			"gitlab/token",                            // free-form path
		} {
			_, err = alice.Logical().Write(path, map[string]any{"id": 21, "name": "alice", "scopes": "read_api"})
			require.Error(t, err, path)
			assert.Contains(t, err.Error(), "permission denied", path)
		}
	})

	t.Run("templated policy: GitLab CI JWT project_id claim picks the project", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		require.NoError(t, err)

		require.NoError(t, sys.EnableAuthWithOptionsWithContext(ctx, "jwt", &api.EnableAuthOptions{Type: "jwt"}))

		_, err = logical.Write("auth/jwt/config", map[string]any{
			"bound_issuer":           "https://gitlab.example.com",
			"jwt_validation_pubkeys": []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))},
		})
		require.NoError(t, err)

		_, err = logical.Write("auth/jwt/role/gitlab-ci", map[string]any{
			"role_type":       "jwt",
			"user_claim":      "project_id",
			"bound_audiences": []string{"https://vault.example.com"},
			"bound_claims":    map[string]any{"namespace_path": "mygroup"},
			"claim_mappings":  map[string]any{"project_id": "project_id", "project_path": "project_path"},
			"token_policies":  []string{"gitlab-ci"},
			"token_ttl":       "10m",
		})
		require.NoError(t, err)

		auths, err := sys.ListAuthWithContext(ctx)
		require.NoError(t, err)

		accessor := auths["jwt/"].Accessor
		require.NoError(t, sys.PutPolicyWithContext(ctx, "gitlab-ci", fmt.Sprintf(`
path "gitlab/dynamic/project_id/{{identity.entity.aliases.%[1]s.metadata.project_id}}/name/ci-*" {
  capabilities = ["create", "update"]
}`, accessor)))

		idToken := func(projectID string) string {
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
			require.NoError(t, err)

			now := time.Now()
			raw, err := josejwt.Signed(signer).Claims(map[string]any{
				"iss":            "https://gitlab.example.com",
				"aud":            "https://vault.example.com",
				"sub":            "project_path:mygroup/app:ref_type:branch:ref:main",
				"iat":            now.Unix(),
				"nbf":            now.Unix(),
				"exp":            now.Add(5 * time.Minute).Unix(),
				"namespace_path": "mygroup",
				"project_id":     projectID,
				"project_path":   "mygroup/app-" + projectID,
			}).Serialize()
			require.NoError(t, err)

			return raw
		}

		job := loginAs(t, client, "auth/jwt/login", map[string]any{"role": "gitlab-ci", "jwt": idToken("31")})

		_, err = job.Logical().Write("gitlab/dynamic/project_id/31/name/ci-deploy", map[string]any{"scopes": "read_api", "ttl": "10m"})
		require.NoError(t, err, "a CI job may mint a token for its own project")

		_, err = job.Logical().Write("gitlab/dynamic/project_id/32/name/ci-deploy", map[string]any{"scopes": "read_api"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "permission denied", "but not for another project")

		other := loginAs(t, client, "auth/jwt/login", map[string]any{"role": "gitlab-ci", "jwt": idToken("32")})

		_, err = other.Logical().Write("gitlab/dynamic/project_id/32/name/ci-deploy", map[string]any{"scopes": "read_api", "ttl": "10m"})
		require.NoError(t, err, "each project gets its own entity (user_claim=project_id)")
	})

	t.Run("path help and openapi", func(t *testing.T) {
		resp, err := client.Logical().ReadWithData("gitlab/config", map[string][]string{"help": {"1"}})
		require.NoError(t, err)
		assert.Contains(t, resp.Data["help"], "Gitlab backend")

		r := client.NewRequest(http.MethodGet, "/v1/sys/internal/specs/openapi")
		raw, err := client.RawRequestWithContext(ctx, r) //nolint:staticcheck
		require.NoError(t, err)

		defer raw.Body.Close()

		var spec struct {
			Paths map[string]any `json:"paths"`
		}
		require.NoError(t, json.NewDecoder(raw.Body).Decode(&spec))
		assert.Contains(t, spec.Paths, "/gitlab/config")
		assert.Contains(t, spec.Paths, "/gitlab/dynamic/project_id/{id}/name/{name}")
	})
}
