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

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	goutils "github.com/jkaninda/go-utils"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type GitProvider struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	URL      string        `yaml:"url" json:"url"` // Git URL
	Branch   string        `yaml:"branch,omitempty" json:"branch,omitempty"`
	Path     string        `yaml:"path,omitempty" json:"path,omitempty"` // Subdirectory in repo
	Interval time.Duration `yaml:"interval" json:"interval"`
	Auth     *GitAuth      `yaml:"auth,omitempty" json:"auth,omitempty"`
	CloneDir string        `yaml:"cloneDir,omitempty" json:"cloneDir,omitempty"` // Local clone directory
}

type GitAuth struct {
	Type       string `yaml:"type" json:"type"` // "token", "ssh", "basic"
	Token      string `yaml:"token,omitempty" json:"token,omitempty"`
	Username   string `yaml:"username,omitempty" json:"username,omitempty"`
	Password   string `yaml:"password,omitempty" json:"password,omitempty"`
	SSHKeyPath string `yaml:"sshKeyPath,omitempty" json:"sshKeyPath,omitempty"`
	SSHKeyData string `yaml:"sshKeyData,omitempty" json:"sshKeyData,omitempty"` // Base64 encoded key
}

type gitProvider struct {
	config *GitProvider
	repo   *git.Repository
	auth   transport.AuthMethod

	mu         sync.RWMutex
	lastCommit string
	lastBundle *ConfigBundle
	stopCh     chan struct{}
	stopped    bool
	clonePath  string
}

func NewGitProvider(cfg *GitProvider) (Provider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("git provider is not enabled")
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("repository URL is required")
	}

	// Set defaults
	if cfg.Interval == 0 {
		cfg.Interval = 120 * time.Second
	}

	if cfg.CloneDir == "" {
		cfg.CloneDir = filepath.Join(os.TempDir(), "goma/providers/git")
	}
	// Default to main branch if neither specified
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}

	provider := &gitProvider{
		config:    cfg,
		stopCh:    make(chan struct{}),
		clonePath: cfg.CloneDir,
	}

	// Setup authentication
	if err := provider.setupAuth(); err != nil {
		return nil, fmt.Errorf("failed to setup authentication: %w", err)
	}

	return provider, nil
}

func (p *gitProvider) Name() ProviderType {
	return GitProviderType
}

func (p *gitProvider) setupAuth() error {
	if p.config.Auth == nil {
		// No authentication
		return nil
	}

	switch p.config.Auth.Type {
	case "token":
		if p.config.Auth.Token == "" {
			return fmt.Errorf("token is required for token authentication")
		}
		p.auth = &http.BasicAuth{
			Username: "git",
			Password: goutils.ReplaceEnvVars(p.config.Auth.Token),
		}

	case "basic":
		if p.config.Auth.Username == "" || p.config.Auth.Password == "" {
			return fmt.Errorf("username and password are required for basic authentication")
		}
		p.auth = &http.BasicAuth{
			Username: goutils.ReplaceEnvVars(p.config.Auth.Username),
			Password: goutils.ReplaceEnvVars(p.config.Auth.Password),
		}

	case "ssh":
		auth, err := p.setupSSHAuth()
		if err != nil {
			return fmt.Errorf("failed to setup SSH authentication: %w", err)
		}
		p.auth = auth

	default:
		return fmt.Errorf("unsupported auth type: %s", p.config.Auth.Type)
	}

	return nil
}

func (p *gitProvider) setupSSHAuth() (transport.AuthMethod, error) {
	var sshKey []byte
	var err error

	// Load SSH key from file or data
	if p.config.Auth.SSHKeyPath != "" {
		sshKey, err = os.ReadFile(goutils.ReplaceEnvVars(p.config.Auth.SSHKeyPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH key file: %w", err)
		}
	} else if p.config.Auth.SSHKeyData != "" {
		// Decode base64 encoded key
		sshKey, err = base64.StdEncoding.DecodeString(goutils.ReplaceEnvVars(p.config.Auth.SSHKeyData))
		if err != nil {
			return nil, fmt.Errorf("failed to decode SSH key data: %w", err)
		}
	} else {
		return nil, fmt.Errorf("SSH key path or data is required for SSH authentication")
	}

	// Parse the SSH key
	signer, err := cryptoSSH.ParsePrivateKey(sshKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	// Create SSH auth
	auth := &ssh.PublicKeys{
		User:   "git",
		Signer: signer,
		HostKeyCallbackHelper: ssh.HostKeyCallbackHelper{
			HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		},
	}

	return auth, nil
}

func (p *gitProvider) Load(ctx context.Context) (*ConfigBundle, error) {
	// Clone or open repository
	if err := p.ensureRepository(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure repository: %w", err)
	}

	// Pull latest changes
	if err := p.pull(ctx); err != nil {
		logger.Error("failed to pull repository", "provider", GitProviderType, "error", err)
		// Load configuration files
		bundle, err := p.loadConfigFiles()
		if err != nil {
			return nil, fmt.Errorf("failed to load config files: %w", err)
		}
		return bundle, nil
	}

	// Get current commit hash
	ref, err := p.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}

	commitHash := ref.Hash().String()

	p.mu.Lock()
	p.lastCommit = commitHash
	p.mu.Unlock()

	// Load configuration files
	bundle, err := p.loadConfigFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to load config files: %w", err)
	}

	// Set version from commit hash
	bundle.Version = fmt.Sprintf("git-%s", commitHash[:8])
	bundle.Timestamp = time.Now()
	bundle.Checksum = bundle.CalculateChecksum()

	// Validate
	if err = bundle.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	p.mu.Lock()
	p.lastBundle = bundle
	p.mu.Unlock()

	logger.Debug("successfully loaded configuration from git",
		"repository", p.config.URL,
		"branch", p.getBranchOrTag(),
		"commit", commitHash[:8],
		"routes", len(bundle.Routes),
		"middlewares", len(bundle.Middlewares))

	return bundle, nil
}

func (p *gitProvider) ensureRepository(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if repository already exists
	if p.repo != nil {
		return nil
	}

	// Check if clone directory exists
	if _, err := os.Stat(p.clonePath); err == nil {
		// Try to open existing repository
		repo, err := git.PlainOpen(p.clonePath)
		if err == nil {
			p.repo = repo
			logger.Debug("opened existing git repository", "path", p.clonePath)
			return nil
		}

		// Remove corrupted clone
		logger.Debug("removing corrupted git clone", "path", p.clonePath)
		if err := os.RemoveAll(p.clonePath); err != nil {
			return fmt.Errorf("failed to remove corrupted clone: %w", err)
		}
	}

	// Clone repository
	logger.Debug("cloning git repository", "repository", p.config.URL,
		"path", p.clonePath)

	cloneOptions := &git.CloneOptions{
		URL:  p.config.URL,
		Auth: p.auth,
	}

	// Set reference name based on branch
	if p.config.Branch != "" {
		cloneOptions.ReferenceName = plumbing.NewBranchReferenceName(p.config.Branch)
		cloneOptions.SingleBranch = true
	}

	repo, err := git.PlainCloneContext(ctx, p.clonePath, false, cloneOptions)
	if err != nil {
		return fmt.Errorf("failed to clone repository: %w", err)
	}

	p.repo = repo
	logger.Info("successfully cloned git repository")

	return nil
}

func (p *gitProvider) pull(ctx context.Context) error {
	p.mu.RLock()
	repo := p.repo
	p.mu.RUnlock()

	if repo == nil {
		return fmt.Errorf("repository not initialized")
	}

	// Get worktree
	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Pull changes
	pullOptions := &git.PullOptions{
		Auth:         p.auth,
		RemoteName:   "origin",
		SingleBranch: true,
	}

	if p.config.Branch != "" {
		pullOptions.ReferenceName = plumbing.NewBranchReferenceName(p.config.Branch)
	}

	logger.Debug("pulling latest changes",
		"branch", p.config.Branch)

	err = worktree.PullContext(ctx, pullOptions)
	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			logger.Debug("repository already up to date")
			return nil
		}
		return fmt.Errorf("failed to pull: %w", err)
	}

	logger.Debug("successfully pulled changes")
	return nil
}

func (p *gitProvider) loadConfigFiles() (*ConfigBundle, error) {
	bundle := &ConfigBundle{
		Routes:      []Route{},
		Middlewares: []Middleware{},
		Metadata:    make(map[string]string),
	}

	// Determine config directory
	configDir := p.clonePath
	if p.config.Path != "" {
		configDir = filepath.Join(p.clonePath, p.config.Path)
	}

	// Check if directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("config directory does not exist: %s", configDir)
	}

	// Load all configuration files
	configFiles, err := loadAllFiles(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load files: %w", err)
	}

	logger.Debug("found configuration files in git", "count", len(configFiles))

	for _, file := range configFiles {
		logger.Debug("loading configuration file", "file", file)

		configBundle := &ConfigBundle{}
		if err := p.loadFile(file, configBundle); err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", file, err)
		}

		// Append routes and middlewares
		bundle.Routes = append(bundle.Routes, configBundle.Routes...)
		bundle.Middlewares = append(bundle.Middlewares, configBundle.Middlewares...)

	}

	return bundle, nil
}

func (p *gitProvider) loadFile(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ext := filepath.Ext(path)
	switch ext {
	case constJsonExt:
		return json.Unmarshal(data, target)
	case constYamlExt, constYmlExt:
		return yaml.Unmarshal(data, target)
	default:
		return fmt.Errorf("unsupported file extension: %s", ext)
	}
}

func (p *gitProvider) Watch(ctx context.Context, out chan<- *ConfigBundle) error {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return fmt.Errorf("provider already stopped")
	}
	p.mu.Unlock()

	// Initial load
	bundle, err := p.Load(ctx)
	if err != nil {
		return fmt.Errorf("initial load failed: %w", err)
	}

	// Send initial config
	select {
	case out <- bundle:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Start polling
	go p.poll(ctx, out)

	logger.Debug("git provider watcher started",
		"repository", p.config.URL,
		"branch", p.getBranchOrTag(),
		"interval", p.config.Interval)

	return nil
}

func (p *gitProvider) poll(ctx context.Context, out chan<- *ConfigBundle) {
	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("git provider polling stopped: context cancelled")
			return

		case <-p.stopCh:
			logger.Debug("git provider polling stopped")
			return

		case <-ticker.C:
			if err := p.checkForUpdates(ctx, out); err != nil {
				logger.Error("failed to check for updates", "error", err)
			}
		}
	}
}

func (p *gitProvider) checkForUpdates(ctx context.Context, out chan<- *ConfigBundle) error {
	logger.Debug("git provider checking for updates")
	// Pull latest changes
	if err := p.pull(ctx); err != nil {
		return fmt.Errorf("failed to pull changes: %w", err)
	}

	// Get current commit
	ref, err := p.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to get HEAD: %w", err)
	}

	currentCommit := ref.Hash().String()

	p.mu.RLock()
	lastCommit := p.lastCommit
	p.mu.RUnlock()

	// Check if commit changed
	if currentCommit == lastCommit {
		logger.Debug("no changes detected", "commit", currentCommit[:8])
		return nil
	}

	logger.Debug("changes detected",
		"old_commit", lastCommit[:8],
		"new_commit", currentCommit[:8])

	// Load new configuration
	bundle, err := p.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to load updated config: %w", err)
	}

	// Send update
	select {
	case out <- bundle:
		logger.Debug("configuration update sent", "version", bundle.Version)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		logger.Warn("timeout sending configuration update")
	}

	return nil
}

func (p *gitProvider) getBranchOrTag() string {
	if p.config.Branch != "" {
		return fmt.Sprintf("branch:%s", p.config.Branch)
	}
	return "unknown"
}

func (p *gitProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return nil
	}

	p.stopped = true
	if p.stopCh != nil {
		close(p.stopCh)
	}

	logger.Debug("git provider stopped")
	return nil
}
