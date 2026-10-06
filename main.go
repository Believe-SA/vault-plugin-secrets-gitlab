// Copyright 2021 Splunk Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"fmt"
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	gitlabtoken "github.com/splunk/vault-plugin-secrets-gitlab/plugin"
)

// Build metadata, injected by GoReleaser via -ldflags at release time.
var (
	commit = "none"
	date   = "unknown"
)

func main() {
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			_, _ = fmt.Fprintf(os.Stdout, "vault-plugin-secrets-gitlab %s (commit %s, built %s)\n", gitlabtoken.Version, commit, date)

			return
		}
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	err := flags.Parse(os.Args[1:])
	if err != nil {
		logFatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	// ServeMultiplex lets Vault run a single plugin process for every mount of
	// this plugin, which is the recommended mode for Vault 1.12+ and 2.x.
	err = plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: gitlabtoken.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		logFatal(err)
	}
}

func logFatal(err error) {
	logger := hclog.New(&hclog.LoggerOptions{})
	logger.Error("plugin shutting down", "error", err)
	os.Exit(1)
}
