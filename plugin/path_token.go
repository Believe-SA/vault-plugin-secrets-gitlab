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
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Schema for the token. This will map the fields coming in from the
// vault request field map.
var accessTokenSchema = map[string]*framework.FieldSchema{
	"id": {
		Type:        framework.TypeInt,
		Description: "Project ID to create a project access token for",
	},
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the project access token",
	},
	"scopes": {
		Type:        framework.TypeCommaStringSlice,
		Description: "List of scopes",
	},
	"ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "Lease duration. The token is revoked in Gitlab when the lease expires or is revoked. Defaults to the mount default lease TTL",
	},
	"expires_at": {
		Type:        framework.TypeTime,
		Description: "Deprecated: use ttl. Sets the lease to end at this time",
		Deprecated:  true,
	},
	"access_level": {
		Type:        framework.TypeInt,
		Description: "access level of project access token",
	},
}

func tokenDetails(pat *PAT) map[string]any {
	d := map[string]any{
		"token":        pat.Token,
		"id":           pat.ID,
		"name":         pat.Name,
		"scopes":       pat.Scopes,
		"access_level": pat.AccessLevel,
	}

	if pat.ExpiresAt != nil {
		d["expires_at"] = time.Time(*pat.ExpiresAt)
	}

	return d
}

func (b *GitlabBackend) pathTokenCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var tokenStorage TokenStorageEntry
	tokenStorage.retrieve(data)

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to obtain GitLab config - %s", err.Error()), nil
	}

	if config == nil {
		return logical.ErrorResponse("GitLab backend configuration has not been set up"), nil
	}

	err = tokenStorage.assertValid(config.MaxTTL, config.AllowOwnerLevel)
	if err != nil {
		return logical.ErrorResponse("Failed to validate - " + err.Error()), nil
	}

	return b.issueToken(ctx, req, config, &tokenStorage.BaseTokenStorage, tokenStorage.leaseTTL())
}

// There is a correctness check that verifies there is an ExistenceFunc for all
// the paths that have a CreateOperation, so we must define a stub one to pass
// that if needed.
func (b *GitlabBackend) pathTokenExistenceCheck() framework.ExistenceFunc {
	return func(_ context.Context, _ *logical.Request, _ *framework.FieldData) (bool, error) {
		return false, nil
	}
}

// Set up the paths for the roles within vault.
func pathToken(b *GitlabBackend) []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern:        pathPatternToken,
			Fields:         accessTokenSchema,
			ExistenceCheck: b.pathTokenExistenceCheck(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{

					Callback: b.pathTokenCreate,
					Summary:  "Create a project access token",
					Examples: tokenExamples,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathTokenCreate,
				},
			},
			HelpSynopsis:    pathTokenHelpSyn,
			HelpDescription: pathTokenHelpDesc,
		},
		{
			Pattern:        "dynamic/project_id/(?P<id>\\d+)/name/(?P<name>[^/]+)",
			Fields:         accessTokenSchema,
			ExistenceCheck: b.pathTokenExistenceCheck(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{

					Callback: b.pathTokenCreate,
					Summary:  "Create a project access token",
					Examples: flatTokenExamples,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathTokenCreate,
				},
			},
			HelpSynopsis:    "Create a project access token using path for project id and name",
			HelpDescription: "This path allows you to create or update a GitLab token using the project ID and token name.",
		},
	}

	return paths
}

//nolint:gosec
const pathTokenHelpSyn = `Generate a project access token for a given project with token name, scopes.`
const pathTokenHelpDesc = `
This path allows you to generate a project access token. You must supply a project id to generate a token for, a name, which
will be used as a name field in Gitlab, and scopes for the generated project access token.

The token is leased for ttl and revoked in Gitlab when the lease expires or is revoked.
`

var tokenExamples = []framework.RequestExample{
	{
		Description: "Create a project access token",
		Data: map[string]any{
			"id":     1,
			"name":   "MyProjectAccessToken",
			"scopes": []string{"read_api", "read_repository"},
			"ttl":    "1h",
		},
	},
}

var flatTokenExamples = []framework.RequestExample{
	{
		Description: "Create a project access token using path for project id and name, ex: dynamic/project_id/1/name/MyProjectAccessToken",
		Data: map[string]any{
			"scopes": []string{"read_api", "read_repository"},
		},
	},
}
