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
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	secretTypeToken = "gitlab_project_access_token"

	// gitlabMaxTokenLifetime is GitLab's default upper bound for access token
	// expiry. Leases are never allowed to outlive it.
	gitlabMaxTokenLifetime = 365 * 24 * time.Hour

	// expiryBackstopBuffer is added before computing the GitLab expiry date so
	// the token always outlives the lease's latest possible end despite
	// lease-commit latency and clock skew between Vault and the plugin.
	expiryBackstopBuffer = 5 * time.Minute

	day = 24 * time.Hour
)

// GitLab project access tokens expire at midnight UTC on their `expires_at`
// date, so the shortest GitLab-side lifetime is about a day. Vault leases give
// the real lifetime instead: the token is revoked through the GitLab API when
// its lease expires or is revoked, and the GitLab expiry is only a backstop set
// just after the lease's maximum lifetime, in case Vault never revokes it.
func secretToken(b *GitlabBackend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypeToken,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Project access token",
			},
		},
		Renew:  b.secretTokenRenew,
		Revoke: b.secretTokenRevoke,
	}
}

// maxLeaseTTL returns the longest lease a token may have on this mount: the
// configured max_ttl, bounded by the mount's max lease TTL and GitLab's limit.
func (b *GitlabBackend) maxLeaseTTL(config *ConfigStorageEntry) time.Duration {
	maxTTL := b.System().MaxLeaseTTL()
	if config.MaxTTL > 0 && config.MaxTTL < maxTTL {
		maxTTL = config.MaxTTL
	}

	return min(maxTTL, gitlabMaxTokenLifetime-day)
}

// gitlabExpiry returns the GitLab expires_at backstop for a token issued at
// now whose lease can last at most maxTTL: the first UTC midnight after the
// lease's latest possible end, with a small buffer so the token can never
// expire before a lease that runs right up to its cap.
func gitlabExpiry(now time.Time, maxTTL time.Duration) time.Time {
	return now.UTC().Add(maxTTL + expiryBackstopBuffer).Truncate(day).Add(day)
}

// issueToken creates a project access token and wraps it in a lease of ttl
// (the mount default when zero).
func (b *GitlabBackend) issueToken(ctx context.Context, req *logical.Request, config *ConfigStorageEntry, base *BaseTokenStorageEntry, ttl time.Duration) (*logical.Response, error) {
	maxTTL := b.maxLeaseTTL(config)

	if ttl <= 0 {
		ttl = min(b.System().DefaultLeaseTTL(), maxTTL)
	}

	if ttl > maxTTL {
		return logical.ErrorResponse("Failed to validate - requested ttl '%s' exceeds the maximum lease ttl of '%s'", ttl, maxTTL), nil
	}

	gc, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to obtain gitlab client - %s", err.Error()), nil
	}

	expiresAt := gitlabExpiry(time.Now(), maxTTL)

	b.Logger().Debug("generating access token", "id", base.ID, "name", base.Name, "scopes", base.Scopes,
		"ttl", ttl, "max_ttl", maxTTL, "gitlab_expires_at", expiresAt)

	pat, err := gc.CreateProjectAccessToken(base, &expiresAt)
	if err != nil {
		return logical.ErrorResponse("Failed to create a token - " + err.Error()), nil
	}

	resp := b.Secret(secretTypeToken).Response(tokenDetails(pat), map[string]any{
		"project_id": base.ID,
		"token_id":   pat.ID,
		"max_ttl":    int64(maxTTL / time.Second),
		// revocation must target the instance that issued the token, even if
		// base_url is reconfigured while the lease is outstanding
		"base_url": config.BaseURL,
	})
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL
	resp.Secret.Renewable = true

	return resp, nil
}

func (b *GitlabBackend) secretTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	maxTTL, err := internalInt(req.Secret.InternalData, "max_ttl")
	if err != nil {
		return nil, err
	}

	// The GitLab expiry was set past issue time + max_ttl, so any extension
	// LeaseExtend allows is still backed by a valid token.
	return framework.LeaseExtend(0, time.Duration(maxTTL)*time.Second, b.System())(ctx, req, d)
}

func (b *GitlabBackend) secretTokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	projectID, err := internalInt(req.Secret.InternalData, "project_id")
	if err != nil {
		return nil, err
	}

	tokenID, err := internalInt(req.Secret.InternalData, "token_id")
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		// Deconfigured backend: there is no credential to revoke with. Clear
		// the lease instead of wedging it forever; the GitLab-side expiry
		// backstop reclaims the token.
		b.Logger().Warn("backend not configured at revoke; relying on the token expiry backstop",
			"project_id", projectID, "token_id", tokenID)

		return nil, nil
	}

	// A lease records the base_url it was issued under. If base_url has been
	// reconfigured since, do NOT contact the old host: that would hand the
	// current parent token to whoever controls the stale hostname. Skip the
	// remote call and let the GitLab-side expiry backstop reclaim the token.
	if issuer, _ := req.Secret.InternalData["base_url"].(string); issuer != "" && issuer != config.BaseURL {
		b.Logger().Warn("lease was issued by a different gitlab instance; skipping remote revocation, the token expires at its backstop date",
			"issuer", issuer, "configured", config.BaseURL, "project_id", projectID, "token_id", tokenID)

		return nil, nil
	}

	gc, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain gitlab client: %w", err)
	}

	b.Logger().Debug("revoking access token", "project_id", projectID, "token_id", tokenID)

	// Returning an error makes Vault retry the revocation with backoff.
	err = gc.RevokeProjectAccessToken(int(projectID), tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke project %d access token %d: %w", projectID, tokenID, err)
	}

	return nil, nil
}

// internalInt reads an integer from lease internal data, which comes back
// from storage as a JSON number.
func internalInt(data map[string]any, key string) (int64, error) {
	switch v := data[key].(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	case json.Number:
		return v.Int64()
	case nil:
		return 0, fmt.Errorf("lease internal data is missing %q", key)
	default:
		return 0, errors.New("lease internal data " + key + " has unexpected type " + fmt.Sprintf("%T", v))
	}
}
