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
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// NoTTLWarning returns a warning message for missing TTL for the provided ttl flag name.
func NoTTLWarning(s string) string {
	return s + " is not set. Token leases are bounded by the mount's max lease TTL only"
}

// Schema for the configuring Gitlab token plugin, this will map the fields coming in from the
// vault request field map.
var configSchema = map[string]*framework.FieldSchema{
	"base_url": {
		Type:        framework.TypeString,
		Description: `gitlab base url (https required; plain http is only accepted for loopback addresses)`,
		Default:     "https://gitlab.com",
	},
	"token": {
		Type:        framework.TypeString,
		Description: `gitlab token that has permissions to generate project access tokens`,
		DisplayAttrs: &framework.DisplayAttributes{
			Sensitive: true,
		},
	},
	"max_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: `Maximum lease duration of a generated token, renewals included. Sub-day values are honored: the token is revoked in Gitlab when its lease ends. If <= 0, the mount's max lease TTL applies`,
		Default:     0,
	},
	"allow_owner_level": {
		Type:        framework.TypeBool,
		Description: "allow to create roles with owner level access",
		Required:    false,
		Default:     false,
	},
}

func configDetail(config *ConfigStorageEntry) map[string]any {
	return map[string]any{
		"base_url":          config.BaseURL,
		"max_ttl":           int64(config.MaxTTL / time.Second),
		"allow_owner_level": config.AllowOwnerLevel,
	}
}

func (b *GitlabBackend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: configDetail(config),
	}, nil
}

//nolint:gocyclo,cyclop,funlen
func (b *GitlabBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	warnings := []string{}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &ConfigStorageEntry{}
	}

	baseURL, ok := data.GetOk("base_url")
	if ok {
		var valid bool

		config.BaseURL, valid = baseURL.(string)
		if !valid {
			return nil, errors.New("string type assertion failed for data field 'base_url'")
		}
	} else if config.BaseURL == "" {
		config.BaseURL, ok = configSchema["base_url"].Default.(string)
		if !ok {
			return nil, errors.New("string type assertion failed for data field 'base_url'")
		}
	}

	if token, ok := data.GetOk("token"); ok {
		config.Token, ok = token.(string)
		if !ok {
			return nil, errors.New("string type assertion failed for data field 'token'")
		}
	}

	maxTTLRaw, ok := data.GetOk("max_ttl")
	if ok {
		maxTTL, valid := maxTTLRaw.(int)
		if !valid {
			return nil, errors.New("int type assertion failed for data field 'max_ttl'")
		}

		// Sub-day values are fine: GitLab still gets a day-granular expiry
		// (see gitlabExpiry) and Vault revokes the token when the lease ends.
		config.MaxTTL = time.Duration(max(maxTTL, 0)) * time.Second
	}

	if config.MaxTTL == 0 {
		warnings = append(warnings, NoTTLWarning("max_ttl"))
	}

	allowOwnerLevel, ok := data.GetOk("allow_owner_level")
	if ok {
		var valid bool

		config.AllowOwnerLevel, valid = allowOwnerLevel.(bool)
		if !valid {
			return nil, errors.New("bool type assertion failed for data field 'allow_owner_level'")
		}
	}

	// maxTTLRaw, ok := data.GetOk("max_ttl")
	// if ok && maxTTLRaw.(int) > 0 {
	// 	config.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	// } else if config.MaxTTL == time.Duration(0) {
	// 	config.MaxTTL = time.Duration(configSchema["max_ttl"].Default.(int)) * time.Second
	// }

	err = validateBaseURL(config.BaseURL)
	if err != nil {
		return logical.ErrorResponse("invalid base_url - " + err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(pathPatternConfig, config)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	// drop the cached client so the new base_url/token take effect immediately
	b.reset()

	return &logical.Response{
		Data:     configDetail(config),
		Warnings: warnings,
	}, nil
}

// validateBaseURL requires base_url to be an https URL, so the parent token
// never transits in cleartext. Plain http is allowed only for loopback
// addresses (local development and the CI acceptance environment).
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}

		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return nil
		}

		return errors.New("plain http is only allowed for loopback addresses; use https so the parent token does not transit in cleartext")
	default:
		return errors.New("must be an http(s) URL")
	}
}

func pathConfig(b *GitlabBackend) []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern: pathPatternConfig,
			Fields:  configSchema,

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Examples: configExamples,
				},
			},

			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		},
	}

	return paths
}

const pathConfigHelpSyn = `
Configure the Gitlab backend.
`

const pathConfigHelpDesc = `
The Gitlab backend requires credentials for creating a project access token.
This endpoint is used to configure those credentials as well as default values
for the backend in general.
`

var configExamples = []framework.RequestExample{
	{
		Description: "Create/update backend configuration",
		Data: map[string]any{
			"base_url":          "https://my.gitlab.com",
			"token":             "MyPersonalAccessToken",
			"max_ttl":           "168h",
			"allow_owner_level": true,
		},
	},
}
