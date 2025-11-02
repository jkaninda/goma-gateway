/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package internal

// PluginConfig defines how plugins are loaded into Goma Gateway.
type PluginConfig struct {
	// Path defines the local directory where plugins (.so files) are located.
	Path string `yaml:"path,omitempty"`
	// Remotes defines one or more remote plugin repositories to fetch.
	Remotes []RemotePlugin `yaml:"remotes,omitempty"`
}

// RemotePlugin represents a remote plugin source (e.g., Git repository).
type RemotePlugin struct {
	// URL is the Git repository URL.
	URL string `yaml:"url"`

	// Version is an optional branch, tag, or commit hash to checkout.
	Version string `yaml:"version,omitempty"`

	// Path is an optional subdirectory within the repo that contains the plugin source.
	Path string `yaml:"path,omitempty"`

	// Auth provides optional authentication for private repositories.
	Auth *PluginAuth `yaml:"auth,omitempty"`
}

// PluginAuth defines authentication credentials for private repositories.
type PluginAuth struct {
	// Token is a personal access token for HTTPS-based Git.
	Token string `yaml:"token,omitempty"`

	// SSHKeyPath is the path to a private SSH key for Git over SSH.
	SSHKeyPath string `yaml:"sshKeyPath,omitempty"`
}
