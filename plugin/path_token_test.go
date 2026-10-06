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
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

//nolint:funlen
func TestAccToken(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test (short)")
	}

	req, backend := newGitlabAccEnv(t)

	ID := envAsInt("GITLAB_PROJECT_ID", 1)

	t.Run("successfully create", func(t *testing.T) {
		t.Parallel()

		d := map[string]any{
			"id":     ID,
			"name":   "vault-test",
			"scopes": []string{"read_api"},
		}
		resp, err := testIssueToken(t, backend, req, d)
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.NotEmpty(t, resp.Data["token"], "no token returned")
		assert.NotEmpty(t, resp.Data["id"], "no id returned")
	})

	t.Run("successfully create with expiration", func(t *testing.T) {
		t.Parallel()

		e := time.Now().Add(time.Hour * 24)
		d := map[string]any{
			"id":         ID,
			"name":       "vault-test-expires",
			"scopes":     []string{"read_api"},
			"expires_at": e.Unix(),
		}
		resp, err := testIssueToken(t, backend, req, d)
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.NotEmpty(t, resp.Data["token"], "no token returned")
		assert.NotEmpty(t, resp.Data["id"], "no id returned")
		expiresAt, _ := resp.Data["expires_at"].(time.Time)
		assert.Equal(t, e.UTC().Format("2006-01-02"), expiresAt.Format("2006-01-02"))
	})

	t.Run("successfully create with access level", func(t *testing.T) {
		t.Parallel()

		e := time.Now().Add(time.Hour * 24)
		d := map[string]any{
			"id":           ID,
			"name":         "vault-test-access-level",
			"scopes":       []string{"read_api"},
			"access_level": 30,
			"expires_at":   e.Unix(),
		}
		resp, err := testIssueToken(t, backend, req, d)
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.NotEmpty(t, resp.Data["token"], "no token returned")
		assert.NotEmpty(t, resp.Data["id"], "no id returned")
		assert.NotEmpty(t, resp.Data["access_level"], "no access_level returned")
		expiresAt, _ := resp.Data["expires_at"].(time.Time)
		assert.Equal(t, e.UTC().Format("2006-01-02"), expiresAt.Format("2006-01-02"))

		assert.Equal(t, gitlab.AccessLevelValue(30), resp.Data["access_level"])
	})

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()

		d := map[string]any{
			"id": -1,
		}
		resp, err := testIssueToken(t, backend, req, d)
		require.NoError(t, err)
		require.True(t, resp.IsError())

		require.Contains(t, resp.Data["error"], "id is empty or invalid")
		require.Contains(t, resp.Data["error"], "name is empty")
		require.Contains(t, resp.Data["error"], "scopes are empty")
	})

	t.Run("exceeding max token lifetime", func(t *testing.T) {
		t.Parallel()

		conf := map[string]any{
			"max_ttl": fmt.Sprintf("%dh", 7*24), // 7 days
		}

		testConfigUpdate(t, backend, req.Storage, conf)

		e := time.Now().Add(time.Hour * 14 * 24)
		d := map[string]any{
			"id":         ID,
			"name":       "vault-test-exceeding-lifetime",
			"scopes":     []string{"read_api"},
			"expires_at": e.Unix(),
		}
		resp, err := testIssueToken(t, backend, req, d)
		require.NoError(t, err)
		require.True(t, resp.IsError())
	})
}

// Create the token given the parameters.
func testIssueToken(t *testing.T, b logical.Backend, req *logical.Request, data map[string]any) (*logical.Response, error) {
	t.Helper()

	// copy: parallel subtests share the same request
	r := *req
	req = &r

	req.Operation = logical.CreateOperation
	req.Path = pathPatternToken
	req.Data = data

	resp, err := b.HandleRequest(context.Background(), req)

	return resp, err
}

// create a token via the flat path (project id and name embedded in the URL).
func testIssueFlatPathToken(t *testing.T, b logical.Backend, req *logical.Request, id int, name string, data map[string]any) (*logical.Response, error) {
	t.Helper()

	// copy: parallel subtests share the same request
	r := *req
	req = &r

	req.Operation = logical.CreateOperation
	req.Path = fmt.Sprintf("dynamic/project_id/%d/name/%s", id, name)
	req.Data = data

	resp, err := b.HandleRequest(context.Background(), req)

	return resp, err
}

//nolint:funlen
func TestFlatPathToken(t *testing.T) {
	t.Parallel()

	t.Run("successfully create", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
		})
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes": []string{"read_api"},
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.Equal(t, "test-token-value", resp.Data["token"])
		assert.EqualValues(t, 1, resp.Data["id"])
		assert.Equal(t, "MyProjectToken", resp.Data["name"])
	})

	t.Run("successfully create with expiration", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
		})
		req := &logical.Request{Storage: storage}

		e := time.Now().Add(time.Hour * 24)
		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes":     []string{"read_api"},
			"expires_at": e.Unix(),
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		assert.Equal(t, "test-token-value", resp.Data["token"])
	})

	t.Run("successfully create with access level", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
		})
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes":       []string{"read_api"},
			"access_level": 30,
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		assert.Equal(t, gitlab.AccessLevelValue(30), resp.Data["access_level"])
	})

	t.Run("validation failure missing scopes", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
		})
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{})
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Data["error"], "scopes are empty")
	})

	t.Run("validation failure invalid access level", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
		})
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes":       []string{"read_api"},
			"access_level": 25, // not a multiple of 10
		})
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Data["error"], "invalid access level")
	})

	t.Run("owner access level denied by default", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
		})
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes":       []string{"read_api"},
			"access_level": 50,
		})
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Data["error"], "access level not permitted")
	})

	t.Run("owner access level allowed when configured", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url":          "https://my.gitlab.com",
			"token":             "mytoken",
			"allow_owner_level": true,
		})
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes":       []string{"read_api"},
			"access_level": 50,
		})
		require.NoError(t, err)
		require.False(t, resp.IsError())
		assert.Equal(t, gitlab.AccessLevelValue(50), resp.Data["access_level"])
	})

	t.Run("exceeding max token lifetime", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		testConfigUpdate(t, backend, storage, map[string]any{
			"base_url": "https://my.gitlab.com",
			"token":    "mytoken",
			"max_ttl":  fmt.Sprintf("%dh", 7*24),
		})
		req := &logical.Request{Storage: storage}

		e := time.Now().Add(time.Hour * 14 * 24)
		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes":     []string{"read_api"},
			"expires_at": e.Unix(),
		})
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Data["error"], "exceeds configured maximum ttl")
	})

	t.Run("no config", func(t *testing.T) {
		t.Parallel()
		backend, storage := getTestBackend(t, true)
		req := &logical.Request{Storage: storage}

		resp, err := testIssueFlatPathToken(t, backend, req, 1, "MyProjectToken", map[string]any{
			"scopes": []string{"read_api"},
		})
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Data["error"], "GitLab backend configuration has not been set up")
	})
}

func TestAccFlatPathToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (short)")
	}

	req, backend := newGitlabAccEnv(t)

	ID := envAsInt("GITLAB_PROJECT_ID", 1)

	t.Run("successfully create", func(t *testing.T) {
		d := map[string]any{
			"scopes": []string{"read_api"},
		}
		resp, err := testIssueFlatPathToken(t, backend, req, ID, "vault-flat-test", d)
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.NotEmpty(t, resp.Data["token"])
		assert.NotEmpty(t, resp.Data["id"])
		assert.Equal(t, "vault-flat-test", resp.Data["name"])
	})

	t.Run("successfully create with expiration", func(t *testing.T) {
		e := time.Now().Add(time.Hour * 24)
		d := map[string]any{
			"scopes":     []string{"read_api"},
			"expires_at": e.Unix(),
		}
		resp, err := testIssueFlatPathToken(t, backend, req, ID, "vault-flat-test-expires", d)
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.NotEmpty(t, resp.Data["token"])
		assert.Equal(t, e.UTC().Format("2006-01-02"), resp.Data["expires_at"].(time.Time).Format("2006-01-02"))
	})

	t.Run("successfully create with access level", func(t *testing.T) {
		e := time.Now().Add(time.Hour * 24)
		d := map[string]any{
			"scopes":       []string{"read_api"},
			"access_level": 30,
			"expires_at":   e.Unix(),
		}
		resp, err := testIssueFlatPathToken(t, backend, req, ID, "vault-flat-test-access-level", d)
		require.NoError(t, err)
		require.False(t, resp.IsError())

		assert.NotEmpty(t, resp.Data["token"])
		assert.Equal(t, gitlab.AccessLevelValue(30), resp.Data["access_level"])
	})

	t.Run("validation failure missing scopes", func(t *testing.T) {
		resp, err := testIssueFlatPathToken(t, backend, req, ID, "vault-flat-test-no-scopes", map[string]any{})
		require.NoError(t, err)
		require.True(t, resp.IsError())
		assert.Contains(t, resp.Data["error"], "scopes are empty")
	})
}
