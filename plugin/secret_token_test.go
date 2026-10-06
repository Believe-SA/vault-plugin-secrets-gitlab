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

package gitlabtoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitlabExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 6, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		maxTTL time.Duration
		want   time.Time
	}{
		// sub-day leases still get a GitLab-valid expiry (tomorrow at the earliest)
		{time.Minute, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)},
		{time.Hour, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)},
		{13 * time.Hour, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)},
		{14 * time.Hour, time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)},
		{48 * time.Hour, time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)},
	}
	for _, tt := range tests {
		t.Run(tt.maxTTL.String(), func(t *testing.T) {
			t.Parallel()

			got := gitlabExpiry(now, tt.maxTTL)
			assert.Equal(t, tt.want, got)
			assert.True(t, got.After(now.Add(tt.maxTTL)), "GitLab expiry must outlive the longest possible lease")
		})
	}

	// Non-UTC input is normalised.
	paris := time.FixedZone("CEST", 2*3600)
	assert.Equal(t, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), gitlabExpiry(now.In(paris), time.Hour))
}

//nolint:ireturn
func newLeaseBackend(t *testing.T, conf map[string]any) (logical.Backend, logical.Storage, *mockGitlabClient) {
	t.Helper()

	b, s, mock := getTestBackendWithMock(t, true)

	c := map[string]any{"base_url": "https://my.gitlab.com", "token": "mytoken"}
	maps.Copy(c, conf)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      pathPatternConfig,
		Data:      c,
		Storage:   s,
	})
	require.NoError(t, err)

	return b, s, mock
}

func createToken(t *testing.T, b logical.Backend, s logical.Storage, path string, data map[string]any) *logical.Response {
	t.Helper()

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      path,
		Data:      data,
		Storage:   s,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	return resp
}

//nolint:funlen
func TestTokenLease(t *testing.T) {
	t.Parallel()

	base := func(extra map[string]any) map[string]any {
		d := map[string]any{"id": 7, "name": "leased", "scopes": []string{"read_api"}}
		maps.Copy(d, extra)

		return d
	}

	t.Run("sub-day ttl yields a short lease and a day-granular gitlab expiry", func(t *testing.T) {
		t.Parallel()

		b, s, mock := newLeaseBackend(t, map[string]any{"max_ttl": "2h"})

		resp := createToken(t, b, s, pathPatternToken, base(map[string]any{"ttl": "15m"}))
		require.False(t, resp.IsError(), resp.Error())
		require.NotNil(t, resp.Secret)

		assert.Equal(t, 15*time.Minute, resp.Secret.TTL)
		assert.Equal(t, 2*time.Hour, resp.Secret.MaxTTL)
		assert.True(t, resp.Secret.Renewable)
		assert.Equal(t, secretTypeToken, resp.Secret.InternalData["secret_type"])
		assert.Equal(t, 7, resp.Secret.InternalData["project_id"])
		assert.Equal(t, int64(7), resp.Secret.InternalData["token_id"])
		assert.Equal(t, "test-token-value", resp.Data["token"])

		require.Len(t, mock.expiresAt, 1)
		sent := *mock.expiresAt[0]
		tomorrow := time.Now().UTC().Truncate(day).Add(day)
		assert.False(t, sent.Before(tomorrow), "GitLab rejects expiries before tomorrow, got %s", sent)
		assert.Equal(t, sent, sent.Truncate(day), "GitLab expiry is a date")
	})

	t.Run("default ttl is the mount default capped by max_ttl", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, map[string]any{"max_ttl": "3h"})

		resp := createToken(t, b, s, pathPatternToken, base(nil))
		require.False(t, resp.IsError(), resp.Error())
		assert.Equal(t, 3*time.Hour, resp.Secret.TTL) // test mount default is 24h
	})

	t.Run("default ttl without max_ttl is the mount default", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		resp := createToken(t, b, s, pathPatternToken, base(nil))
		require.False(t, resp.IsError(), resp.Error())

		gb, _ := b.(*GitlabBackend)
		assert.Equal(t, gb.System().DefaultLeaseTTL(), resp.Secret.TTL)
		assert.Equal(t, gb.System().MaxLeaseTTL(), resp.Secret.MaxTTL)
	})

	t.Run("ttl above max_ttl is rejected", func(t *testing.T) {
		t.Parallel()

		b, s, mock := newLeaseBackend(t, map[string]any{"max_ttl": "1h"})

		resp := createToken(t, b, s, pathPatternToken, base(map[string]any{"ttl": "2h"}))
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Error().Error(), "exceeds configured maximum ttl")
		assert.Empty(t, mock.expiresAt, "nothing must be created in GitLab")
	})

	t.Run("ttl above the mount max lease is rejected", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		gb, _ := b.(*GitlabBackend)
		tooLong := gb.System().MaxLeaseTTL() + time.Hour

		resp := createToken(t, b, s, pathPatternToken, base(map[string]any{"ttl": fmt.Sprintf("%ds", int(tooLong.Seconds()))}))
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Error().Error(), "exceeds the maximum lease ttl")
	})

	t.Run("ttl and expires_at are mutually exclusive", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		resp := createToken(t, b, s, pathPatternToken, base(map[string]any{
			"ttl": "1h", "expires_at": time.Now().Add(2 * time.Hour).Unix(),
		}))
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Error().Error(), "mutually exclusive")
	})

	t.Run("deprecated expires_at sets the lease end", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		resp := createToken(t, b, s, pathPatternToken, base(map[string]any{
			"expires_at": time.Now().Add(5 * time.Hour).Unix(),
		}))
		require.False(t, resp.IsError(), resp.Error())
		assert.InDelta(t, (5 * time.Hour).Seconds(), resp.Secret.TTL.Seconds(), 5)
	})

	t.Run("expires_at in the past is rejected", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		resp := createToken(t, b, s, pathPatternToken, base(map[string]any{
			"expires_at": time.Now().Add(-time.Hour).Unix(),
		}))
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Error().Error(), "in the past")
	})

	t.Run("flat path is leased", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		resp := createToken(t, b, s, "dynamic/project_id/9/name/flat", map[string]any{"scopes": "read_api", "ttl": "30m"})
		require.False(t, resp.IsError(), resp.Error())
		assert.Equal(t, 30*time.Minute, resp.Secret.TTL)
		assert.Equal(t, 9, resp.Secret.InternalData["project_id"])
	})

	t.Run("role token lease uses token_ttl", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, map[string]any{"max_ttl": "4h"})
		mustRoleCreate(t, b, s, "short", base(map[string]any{"token_ttl": "20m"}))

		resp := createToken(t, b, s, pathPatternToken+"/short", nil)
		require.False(t, resp.IsError(), resp.Error())
		assert.Equal(t, 20*time.Minute, resp.Secret.TTL)
		assert.Equal(t, 4*time.Hour, resp.Secret.MaxTTL)
	})
}

func secretRequest(op logical.Operation, s logical.Storage, secret *logical.Secret) *logical.Request {
	secret.IssueTime = time.Now()

	return &logical.Request{Operation: op, Storage: s, Secret: secret}
}

// roundTrip mimics Vault persisting the lease: internal data comes back as JSON.
func roundTrip(t *testing.T, secret *logical.Secret) *logical.Secret {
	t.Helper()

	raw, err := json.Marshal(secret.InternalData)
	require.NoError(t, err)

	internal := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &internal))

	out := *secret
	out.InternalData = internal

	return &out
}

//nolint:funlen
func TestTokenRevoke(t *testing.T) {
	t.Parallel()

	t.Run("revokes the token in gitlab", func(t *testing.T) {
		t.Parallel()

		b, s, mock := newLeaseBackend(t, nil)
		resp := createToken(t, b, s, pathPatternToken, map[string]any{"id": 42, "name": "x", "scopes": "api", "ttl": "1h"})
		require.False(t, resp.IsError(), resp.Error())

		_, err := b.HandleRequest(context.Background(), secretRequest(logical.RevokeOperation, s, roundTrip(t, resp.Secret)))
		require.NoError(t, err)
		assert.Equal(t, [][2]int64{{42, 42}}, mock.revoked)
	})

	t.Run("revokes against the issuing instance after base_url changes", func(t *testing.T) {
		t.Parallel()

		b, s, mock := newLeaseBackend(t, nil)
		resp := createToken(t, b, s, pathPatternToken, map[string]any{"id": 3, "name": "x", "scopes": "api"})
		require.False(t, resp.IsError(), resp.Error())

		gb, _ := b.(*GitlabBackend)

		var built []*ConfigStorageEntry

		gb.newClient = func(c *ConfigStorageEntry) (Client, error) {
			built = append(built, c)

			return mock, nil
		}

		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: pathPatternConfig, Storage: s,
			Data: map[string]any{"base_url": "https://new.gitlab.com", "token": "new-token"},
		})
		require.NoError(t, err)

		_, err = b.HandleRequest(context.Background(), secretRequest(logical.RevokeOperation, s, roundTrip(t, resp.Secret)))
		require.NoError(t, err)

		require.Len(t, built, 1)
		assert.Equal(t, "https://my.gitlab.com", built[0].BaseURL, "must revoke where the token was issued")
		assert.Equal(t, "new-token", built[0].Token)
		assert.Equal(t, [][2]int64{{3, 3}}, mock.revoked)
	})

	t.Run("gitlab failure is returned so vault retries", func(t *testing.T) {
		t.Parallel()

		b, s, mock := newLeaseBackend(t, nil)
		resp := createToken(t, b, s, pathPatternToken, map[string]any{"id": 1, "name": "x", "scopes": "api"})
		require.False(t, resp.IsError(), resp.Error())

		mock.revokeErr = errors.New("gitlab is down")

		_, err := b.HandleRequest(context.Background(), secretRequest(logical.RevokeOperation, s, resp.Secret))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gitlab is down")
	})

	t.Run("missing internal data", func(t *testing.T) {
		t.Parallel()

		b, s, _ := newLeaseBackend(t, nil)

		_, err := b.HandleRequest(context.Background(), secretRequest(logical.RevokeOperation, s, &logical.Secret{
			InternalData: map[string]any{"secret_type": secretTypeToken},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "project_id")
	})
}

func TestTokenRenew(t *testing.T) {
	t.Parallel()

	b, s, _ := newLeaseBackend(t, map[string]any{"max_ttl": "2h"})
	resp := createToken(t, b, s, pathPatternToken, map[string]any{"id": 1, "name": "x", "scopes": "api", "ttl": "30m"})
	require.False(t, resp.IsError(), resp.Error())

	// Vault core applies the increment and caps the lease at MaxTTL counted
	// from the original issue time; the plugin must hand back that MaxTTL.
	secret := roundTrip(t, resp.Secret)
	secret.Increment = time.Hour

	renewed, err := b.HandleRequest(context.Background(), secretRequest(logical.RenewOperation, s, secret))
	require.NoError(t, err)
	require.NotNil(t, renewed.Secret)
	assert.Equal(t, 2*time.Hour, renewed.Secret.MaxTTL)
}
