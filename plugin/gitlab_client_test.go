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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestNewClientFail(t *testing.T) {
	t.Parallel()
	t.Run("no config", func(t *testing.T) {
		t.Parallel()

		c, err := NewClient(nil)
		require.Error(t, err, "nil config should thrown an error when retrieving Gitlab client")
		assert.Nil(t, c, "NewClient should return nil client on error")
	})

	t.Run("empty config", func(t *testing.T) {
		t.Parallel()

		config := &ConfigStorageEntry{}
		c, err := NewClient(config)
		require.Error(t, err, "NewClient should return an error if config is missing auth")
		assert.Nil(t, c, "NewClient should return nil client on error")
	})
}

func TestValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		client   *GitlabClient
		asserter assert.BoolAssertionFunc
	}{
		{
			name: "valid",
			client: &GitlabClient{
				expiration: time.Now().Add(clientTTL),
			},
			asserter: assert.True,
		},
		{
			name: "expired",
			client: &GitlabClient{
				expiration: time.Now().Add(-1 * time.Minute),
			},
			asserter: assert.False,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.asserter(t, test.client.Valid())
		})
	}
}

type mockGitlabClient struct {
	mu        sync.Mutex
	expiresAt []*time.Time
	revoked   [][2]int64
	revokeErr error
}

var _ Client = &mockGitlabClient{}

func (ac *mockGitlabClient) Valid() bool {
	return true
}

//	func (ac *mockGitlabClient) ListProjectAccessToken(id int) ([]*PAT, error) {
//		return nil, nil
//	}
func (ac *mockGitlabClient) CreateProjectAccessToken(tokenStorage *BaseTokenStorageEntry, expiresAt *time.Time) (*PAT, error) {
	ac.mu.Lock()
	ac.expiresAt = append(ac.expiresAt, expiresAt)
	ac.mu.Unlock()

	return &PAT{
		PersonalAccessToken: gitlab.PersonalAccessToken{
			ID:     int64(tokenStorage.ID),
			Name:   tokenStorage.Name,
			Token:  "test-token-value",
			Scopes: tokenStorage.Scopes,
		},
		AccessLevel: gitlab.AccessLevelValue(tokenStorage.AccessLevel),
	}, nil
}

func (ac *mockGitlabClient) RevokeProjectAccessToken(projectID int, tokenID int64) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.revokeErr != nil {
		return ac.revokeErr
	}

	ac.revoked = append(ac.revoked, [2]int64{int64(projectID), tokenID})

	return nil
}
