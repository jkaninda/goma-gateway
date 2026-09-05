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

// Package certmanager provides functionality for managing TLS certificates,
// including ACME certificates from one or more named providers.
package certmanager

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/jkaninda/logger"
	"github.com/robfig/cron/v3"
)

// Domain represents a domain configuration owned by a route.
type Domain struct {
	Name  string
	Hosts []string
}

// AcmeConfig holds ACME-specific configuration. Retained for JSON storage compatibility.
type AcmeConfig struct {
	Email         string      `json:"email"`
	DirectoryURL  string      `json:"directory_url"`
	ChallengeType string      `json:"challenge_type"`
	DnsProvider   string      `json:"dns_provider"`
	StorageFile   string      `json:"storage_file"`
	Credentials   Credentials `json:"credentials"`
}

// Storage types
type (
	StoredUserAccount struct {
		Email        string `json:"email"`
		PrivateKey   string `json:"private_key"`
		Registration string `json:"registration"`
		EabKid       string `json:"eab_kid,omitempty"`
	}

	StoredCertificate struct {
		Domain      string    `json:"domain"`
		Certificate string    `json:"certificate"`
		PrivateKey  string    `json:"private_key"`
		Domains     []string  `json:"domains"`
		Expires     time.Time `json:"expires"`
		IssuedAt    time.Time `json:"issued_at"`
	}

	CertificateStorage struct {
		UserAccount  *StoredUserAccount   `json:"user_account"`
		Certificates []*StoredCertificate `json:"certificates"`
		Version      string               `json:"version"`
		UpdatedAt    time.Time            `json:"updated_at"`
	}
	ProcessingStats struct {
		Success int
		Errors  int
		Skipped int
	}
)

// CertificateInfo contains certificate information.
type CertificateInfo struct {
	Certificate *tls.Certificate
	Domains     []string
	Expires     time.Time
	IssuedAt    time.Time
	Resource    *certificate.Resource
}

// LegoUser implements the lego User interface.
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
	// eabKid is the external account binding key id this account was
	// registered under, empty when it was registered without one. Kept so a
	// changed credential in the config can be detected on the next start.
	eabKid string
}

func (u *LegoUser) GetEmail() string                        { return u.Email }
func (u *LegoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// CertManager orchestrates one or more named cert providers and serves the
// gateway's TLS GetCertificate callback. Per-provider ACME state lives in the
// private *provider type; route-level / file-loaded certs and the default
// self-signed cert are shared across providers.
type CertManager struct {
	mu              sync.RWMutex
	providers       map[string]*provider
	defaultProvider string
	customCerts     map[string]*CertificateInfo
	defaultCert     *tls.Certificate
	config          *Config

	onDemandMu       sync.Mutex
	onDemandAttempts map[string]*onDemandAttempt
}

// onDemandAttempt throttles the SNI-triggered certificate request for one host,
// so a name that keeps failing validation is retried on a widening interval
// rather than on every handshake.
type onDemandAttempt struct {
	nextAttempt time.Time
	failures    int
}

// provider holds per-provider ACME state. One *provider per entry in
// Config.Providers; each gets its own Lego client and storage file.
type provider struct {
	mu                 sync.RWMutex
	name               string
	cfg                ProviderConfig
	legoClient         *lego.Client
	user               *LegoUser
	storageFile        string
	cacheDir           string
	certs              map[string]*CertificateInfo
	allowedHosts       []Domain
	inProgressRequests map[string]bool
	acmeInitialized    bool
	vaultClient        *vaultPKIClient
	cronJob            *cron.Cron
}

// NewCertManager creates a CertManager from a (possibly legacy) Config. The
// config is normalized in place — top-level Provider/Acme/Vault fields are
// migrated into Providers["default"] for backward compatibility.
func NewCertManager(config *Config) (*CertManager, error) {
	if config == nil {
		config = &Config{}
	}
	config.Normalize()

	cm := &CertManager{
		providers:       make(map[string]*provider),
		defaultProvider: config.DefaultProvider,
		customCerts:     make(map[string]*CertificateInfo),
		config:          config,
	}

	for name, pcfg := range config.Providers {
		p, err := newProvider(name, pcfg)
		if err != nil {
			return nil, fmt.Errorf("provider %q: %w", name, err)
		}
		cm.providers[name] = p
	}
	return cm, nil
}

func newProvider(name string, cfg ProviderConfig) (*provider, error) {
	storageFile := cfg.Acme.StorageFile
	if cfg.Type == CertVaultProvider {
		storageFile = cfg.Vault.StorageFile
	}
	storageConfig, err := initializeProviderStorageConfig(name, cfg.Type, storageFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage configuration: %w", err)
	}
	return &provider{
		name:               name,
		cfg:                cfg,
		certs:              make(map[string]*CertificateInfo),
		storageFile:        storageConfig.StorageFile,
		cacheDir:           storageConfig.CacheDir,
		inProgressRequests: make(map[string]bool),
		cronJob:            cron.New(),
	}, nil
}

// Initialize sets up every configured provider. Errors from individual
// providers are logged; if at least one is missing required config (e.g. no
// email), that error is propagated so the operator sees it. ACME providers
// that fail mid-setup leave the CertManager partially initialized — other
// providers continue to function.
func (cm *CertManager) Initialize() error {
	if len(cm.providers) == 0 {
		logger.Debug("No certmanager providers configured")
		return nil
	}
	var firstErr error
	for _, p := range cm.providers {
		if err := p.initialize(); err != nil {
			if errors.Is(err, ErrorNoEmail) && firstErr == nil {
				firstErr = err
			}
			logger.Error("Failed to initialize provider", "provider", p.name, "error", err)
		}
	}
	return firstErr
}

func (p *provider) initialize() error {
	if p.acmeInitialized {
		logger.Debug("Provider already initialized", "provider", p.name)
		return nil
	}
	if err := p.validateConfig(); err != nil {
		return err
	}

	if p.cfg.Type == CertVaultProvider {
		return p.initializeVault()
	}

	if err := p.loadFromStorage(); err != nil || p.user == nil {
		if err := p.createNewUser(); err != nil {
			return fmt.Errorf("failed to create new user: %w", err)
		}
	} else if p.eabCredentialChanged() {
		logger.Info("ACME external account binding changed, registering a new account",
			"provider", p.name, "kid", p.cfg.Acme.Eab.Kid)
		if err := p.createNewUser(); err != nil {
			return fmt.Errorf("failed to create new user: %w", err)
		}
	}

	if err := p.setupLegoClient(); err != nil {
		return fmt.Errorf("failed to setup lego client: %w", err)
	}

	if err := p.registerUser(); err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	if err := p.setupChallenges(); err != nil {
		return fmt.Errorf("failed to setup challenges: %w", err)
	}
	p.acmeInitialized = true
	return nil
}

func (p *provider) validateConfig() error {
	if p.cfg.Type == CertVaultProvider {
		// Vault credentials are validated when the client is built (they may come
		// from environment variables), so nothing to check here.
		return nil
	}
	if p.cfg.Acme.Email == "" {
		return ErrorNoEmail
	}
	if p.cfg.Acme.ChallengeType == DNS01 {
		if p.cfg.Acme.DnsProvider == "" && p.cfg.Acme.Credentials.ApiToken == "" {
			return errors.New("no DNS provider or API token configured for DNS01 challenge")
		}
	}
	if eab := p.cfg.Acme.Eab; (eab.Kid == "") != (eab.HmacKey == "") {
		return errors.New("external account binding needs both acme.eab.kid and acme.eab.hmacKey")
	}
	return nil
}

func (p *provider) createNewUser() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	p.user = &LegoUser{
		Email:  p.cfg.Acme.Email,
		key:    privateKey,
		eabKid: p.cfg.Acme.Eab.Kid,
	}
	return nil
}

// eabCredentialChanged reports whether the configured external account binding
// key id differs from the one the stored account registered with.
func (p *provider) eabCredentialChanged() bool {
	if p.user == nil || p.user.Registration == nil {
		return false
	}
	return p.user.eabKid != p.cfg.Acme.Eab.Kid
}

func (p *provider) registerUser() error {
	if p.user.Registration != nil {
		return nil
	}

	var (
		reg *registration.Resource
		err error
	)

	agreed := p.cfg.Acme.TermsAgreed()
	if !agreed {
		logger.Warn("Registering with acme.termsAccepted set to false; the CA will most likely refuse",
			"provider", p.name)
	}
	if eab := p.cfg.Acme.Eab; eab.Kid != "" {
		reg, err = p.legoClient.Registration.RegisterWithExternalAccountBinding(
			registration.RegisterEABOptions{
				TermsOfServiceAgreed: agreed,
				Kid:                  eab.Kid,
				HmacEncoded:          eab.HmacKey,
			})
	} else {
		reg, err = p.legoClient.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: agreed,
		})
	}
	if err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}
	p.user.Registration = reg
	p.user.eabKid = p.cfg.Acme.Eab.Kid
	return p.saveToStorage()
}

func (p *provider) setupLegoClient() error {
	config := lego.NewConfig(p.user)
	config.Certificate.KeyType = certcrypto.RSA2048

	if p.cfg.Acme.DirectoryURL != "" {
		config.CADirURL = p.cfg.Acme.DirectoryURL
		p.configureInsecureClientIfNeeded(config)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	if p.cfg.Acme.Eab.Kid == "" && client.GetExternalAccountRequired() {
		return errors.New("this ACME directory requires external account binding: " +
			"set acme.eab.kid and acme.eab.hmacKey")
	}

	p.legoClient = client
	return nil
}

// configureInsecureClientIfNeeded disables TLS verification against the ACME
// directory when the operator has explicitly asked for it.
func (p *provider) configureInsecureClientIfNeeded(config *lego.Config) {
	if !p.cfg.Acme.InsecureSkipVerify {
		return
	}
	logger.Warn("ACME TLS verification is disabled by acme.insecureSkipVerify",
		"directoryUrl", p.cfg.Acme.DirectoryURL)
	config.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // explicitly requested by configuration
			},
		},
	}
}

func (p *provider) setupChallenges() error {
	if p.cfg.Acme.ChallengeType == DNS01 {
		dns, err := p.createDNSProvider()
		if err != nil {
			return fmt.Errorf("failed to create DNS provider: %w", err)
		}
		return p.legoClient.Challenge.SetDNS01Provider(dns)
	}
	return p.legoClient.Challenge.SetHTTP01Provider(
		// Bound to loopback, not 0.0.0.0: the gateway proxies
		// /.well-known/acme-challenge/ to it locally, so there is no reason for
		// the challenge server to be reachable from the network.
		http01.NewProviderServer("127.0.0.1", httpChallengePort),
	)
}

func (p *provider) createDNSProvider() (challenge.Provider, error) {
	switch p.cfg.Acme.DnsProvider {
	case cloudflareProvider:
		if p.cfg.Acme.Credentials.ApiToken == "" {
			return nil, errors.New("cloudflare API token is required")
		}
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthToken = p.cfg.Acme.Credentials.ApiToken
		return cloudflare.NewDNSProviderConfig(cfg)
	case route53Provider:
		return nil, errors.New("route53 provider not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", p.cfg.Acme.DnsProvider)
	}
}

// AutoCert starts automatic certificate management for the legacy single-provider
// case. All domains are routed to the default provider.
func (cm *CertManager) AutoCert(domains []Domain) {
	if cm.defaultProvider == "" {
		logger.Debug("No default provider configured, AutoCert skipped")
		return
	}
	cm.AutoCertByProvider(map[string][]Domain{cm.defaultProvider: domains})
}

// AutoCertByProvider starts automatic certificate management for one or more
// providers, partitioning domains by provider name.
func (cm *CertManager) AutoCertByProvider(byProvider map[string][]Domain) {
	for name, domains := range byProvider {
		p, ok := cm.providers[name]
		if !ok {
			logger.Warn("Skipping AutoCert for unknown provider", "provider", name)
			continue
		}
		p.mu.Lock()
		p.allowedHosts = domains
		p.mu.Unlock()

		p.startRenewalService()
		if err := p.processCertificates(); err != nil {
			logger.Error("Error processing certificates", "provider", name, "error", err)
		}
		logger.Debug("AutoCert started", "provider", name, "domains", len(domains))
	}
}

// UpdateDomains is the legacy single-provider domain update. All domains go to
// the default provider.
func (cm *CertManager) UpdateDomains(domains []Domain) {
	if cm.defaultProvider == "" {
		return
	}
	cm.UpdateDomainsByProvider(map[string][]Domain{cm.defaultProvider: domains})
}

// UpdateDomainsByProvider distributes domains to their owning providers and
// kicks off background certificate processing. Providers not present in the
// map have their allowedHosts cleared so stale routes stop being renewed.
func (cm *CertManager) UpdateDomainsByProvider(byProvider map[string][]Domain) {
	for name, p := range cm.providers {
		domains := byProvider[name]
		if !p.acmeInitialized {
			logger.Debug("Provider not initialized, skipping domain update", "provider", name)
			continue
		}
		p.mu.Lock()
		p.allowedHosts = domains
		p.mu.Unlock()
		logger.Debug("Updated allowed hosts", "provider", name, "count", len(domains))

		go func(p *provider) {
			if err := p.processCertificates(); err != nil {
				logger.Error("Error processing certificates after domain update", "provider", p.name, "error", err)
			}
		}(p)
	}
}

func (p *provider) processCertificates() error {
	stats := &ProcessingStats{}
	var wg sync.WaitGroup

	p.mu.RLock()
	domains := append([]Domain(nil), p.allowedHosts...)
	p.mu.RUnlock()

	for _, domain := range domains {
		if p.shouldSkipDomain(domain, false) {
			stats.Skipped++
			continue
		}

		wg.Add(1)
		go func(d Domain) {
			defer wg.Done()
			if err := p.processDomain(d, stats, false); err != nil {
				time.Sleep(errorDelay)
				return
			}
			time.Sleep(requestDelay)
		}(domain)
	}

	wg.Wait()
	logger.Debug("Processing complete", "provider", p.name, "success", stats.Success, "errors", stats.Errors, "skipped", stats.Skipped)
	return p.validateProcessingResults(stats)
}

func (p *provider) requestNewCertificate(host string, stats *ProcessingStats, renewal bool) error {
	if stats == nil {
		stats = &ProcessingStats{}
	}

	logger.Debug("=== requestNewCertificate ===", "provider", p.name, "host", host)
	allowed, domain := p.isHostAllowed(host)
	if !allowed {
		stats.Skipped++
		logger.Debug("Skipping certificate request, domain not recognized", "provider", p.name, "host", host)
		return nil
	}
	if p.shouldSkipDomain(domain, renewal) {
		stats.Skipped++
		return nil
	}

	if err := p.processDomain(domain, stats, renewal); err != nil {
		if !errors.Is(err, ErrAlreadyInProgress) {
			logger.Error("Failed to process domain", "provider", p.name, "domain", domain.Hosts[0], "error", err)
			time.Sleep(errorDelay)
			return err
		}
		logger.Debug("Certificate request already in progress", "provider", p.name, "host", host, "route", domain.Name, "hosts", domain.Hosts)
		return nil
	}
	stats.Success++
	time.Sleep(requestDelay)
	return nil
}

// shouldSkipDomain reports whether a route needs no certificate work right now.
// The caller owns the Skipped counter.
func (p *provider) shouldSkipDomain(domain Domain, renewal bool) bool {
	if len(domain.Hosts) == 0 {
		return true
	}
	// Only a certificate naming the host counts. A wildcard that merely covers
	// it serves traffic in the meantime, but must not stop the route from
	// getting a certificate of its own.
	if p.hasExactCertificate(domain.Hosts[0], renewal) {
		return true
	}
	if p.isRequestInProgress(domain.Hosts) {
		return true
	}
	return false
}

func (p *provider) processDomain(domain Domain, stats *ProcessingStats, renewal bool) error {
	logger.Debug("Processing domain", "provider", p.name, "domain", domain.Name, "hosts", domain.Hosts)
	cert, err := p.requestCertificateSync(domain, renewal)
	if err != nil {
		logger.Error("Failed to process domain", "provider", p.name, "domain", domain.Name, "error", err)
		stats.Errors++
		return err
	}
	if cert != nil {
		logger.Debug("Certificate obtained", "provider", p.name, "route", domain.Name, "hosts", domain.Hosts)
		stats.Success++
	}
	return nil
}

func (p *provider) validateProcessingResults(stats *ProcessingStats) error {
	if stats.Errors > 0 && stats.Success == 0 {
		return fmt.Errorf("all certificate requests failed (%d errors)", stats.Errors)
	}
	return nil
}

func (p *provider) renewCertificates() {
	logger.Debug("********************* Renewing certificates *********************", "provider", p.name)
	certsToRenew := p.getCertificatesToRenew()
	if len(certsToRenew) == 0 {
		logger.Info("CertManager: No certificates due for renewal", "provider", p.name)
		return
	}
	stats := &ProcessingStats{}

	logger.Info("CertManager: Renewing certificates", "provider", p.name, "count", len(certsToRenew))
	for _, host := range certsToRenew {
		if err := p.requestNewCertificate(host, stats, true); err != nil {
			logger.Error("Error renewing certificate", "provider", p.name, "host", host, "error", err)
			continue
		}
		time.Sleep(requestDelay)
	}
	logger.Info("CertManager: Certificate renewal complete", "provider", p.name, "success", stats.Success, "errors", stats.Errors, "skipped", stats.Skipped)
}

func (p *provider) getCertificatesToRenew() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var certsToRenew []string
	for domain, certInfo := range p.certs {
		if time.Until(certInfo.Expires) <= renewalBufferTime {
			certsToRenew = append(certsToRenew, domain)
		}
	}
	return certsToRenew
}

func (p *provider) requestCertificateSync(domain Domain, renewal bool) (*tls.Certificate, error) {
	if !p.acmeInitialized {
		return nil, errors.New("ACME client not initialized")
	}

	if cert := p.checkExistingValidCertificate(domain, renewal); cert != nil {
		return cert, nil
	}

	if p.isRequestInProgress(domain.Hosts) {
		return nil, fmt.Errorf("certificate request already in progress for domains: %v", domain.Hosts)
	}

	return p.performCertificateRequest(domain)
}

func (p *provider) performCertificateRequest(domain Domain) (*tls.Certificate, error) {
	if p.cfg.Type == CertVaultProvider {
		return p.performVaultCertificateRequest(domain)
	}

	httpChallengeMu.Lock()
	defer httpChallengeMu.Unlock()

	p.markRequestInProgress(domain.Hosts, true)
	defer p.markRequestInProgress(domain.Hosts, false)
	certificates, err := p.legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domain.Hosts,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate from ACME: %w", err)
	}

	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	certInfo := createCertificateInfoFromACME(&cert, domain.Hosts, certificates)
	p.storeCertificateInfo(domain.Hosts, certInfo)

	if err = p.saveToStorage(); err != nil {
		logger.Error("Failed to save certificate to storage", "provider", p.name, "error", err)
	}
	return &cert, nil
}

// initializeVault sets up a Vault PKI provider. Unlike ACME there is no user
// account, registration or challenge; the client just needs valid credentials.
// Previously issued certificates are loaded from storage when present.
func (p *provider) initializeVault() error {
	client, err := newVaultPKIClient(p.cfg.Vault)
	if err != nil {
		return fmt.Errorf("failed to configure vault client: %w", err)
	}
	p.vaultClient = client

	// A missing storage file is expected on first run; other load errors are
	// logged but non-fatal since Vault can re-issue every certificate.
	if err := p.loadFromStorage(); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to load vault certificates from storage", "provider", p.name, "error", err)
	}

	p.acmeInitialized = true
	logger.Info("Vault certificate provider initialized", "provider", p.name)
	return nil
}

// performVaultCertificateRequest issues a certificate through the Vault PKI
// secrets engine and stores it. There is no shared challenge port, so it does
// not take the http challenge lock.
func (p *provider) performVaultCertificateRequest(domain Domain) (*tls.Certificate, error) {
	if p.vaultClient == nil {
		return nil, errors.New("vault client not initialized")
	}

	p.markRequestInProgress(domain.Hosts, true)
	defer p.markRequestInProgress(domain.Hosts, false)

	issued, err := p.vaultClient.IssueCertificate(domain.Hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate from vault: %w", err)
	}

	cert, err := tls.X509KeyPair(issued.CertPEM, issued.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	certInfo, err := createCertificateInfoFromVault(&cert, domain.Hosts)
	if err != nil {
		return nil, err
	}
	p.storeCertificateInfo(domain.Hosts, certInfo)

	if err = p.saveToStorage(); err != nil {
		logger.Error("Failed to save certificate to storage", "provider", p.name, "error", err)
	}
	return &cert, nil
}

// createCertificateInfoFromVault builds a CertificateInfo from a Vault-issued
// certificate, deriving the expiry from the leaf certificate's NotAfter.
func createCertificateInfoFromVault(cert *tls.Certificate, domains []string) (*CertificateInfo, error) {
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse vault certificate: %w", err)
	}
	return &CertificateInfo{
		Certificate: cert,
		Domains:     domains,
		Expires:     parsedCert.NotAfter,
		IssuedAt:    time.Now(),
	}, nil
}

// GetCertificate is the TLS GetCertificate callback. It picks the most specific
// certificate available across the shared customCerts and every provider's
// certs, and finally falls back to the default cert. A certificate that names
// the SNI host explicitly always beats a wildcard certificate that merely
// covers it, whichever pool each one lives in.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := normalizeServerName(hello.ServerName)
	if serverName == "" {
		return cm.getDefaultCertificate()
	}

	certInfo, rank := cm.findBestCertificate(serverName)
	if rank < matchExact {
		cm.requestCertificateOnDemand(serverName)
	}
	if certInfo != nil {
		return certInfo.Certificate, nil
	}
	return cm.getDefaultCertificate()
}

// requestCertificateOnDemand starts a background certificate order for
// serverName with the provider that claims it. It never blocks the handshake,
// and the throttle keeps repeated handshakes for an unissuable host from
// hammering the ACME provider.
func (cm *CertManager) requestCertificateOnDemand(serverName string) {
	owner := cm.providerForSNI(serverName)
	if owner == nil {
		logger.Debug("No provider claims SNI, not requesting a certificate", "server_name", serverName)
		return
	}
	if !cm.beginOnDemandAttempt(serverName) {
		return
	}

	logger.Debug("Requesting a dedicated certificate in the background", "provider", owner.name, "server_name", serverName)
	go func() {
		if err := owner.requestNewCertificate(serverName, nil, false); err != nil {
			logger.Error("Background certificate request failed", "provider", owner.name, "server_name", serverName, "error", err)
		}
		cm.finishOnDemandAttempt(serverName)
	}()
}

// beginOnDemandAttempt reports whether an on-demand order for serverName may
// start now, reserving the slot so concurrent handshakes do not stampede.
func (cm *CertManager) beginOnDemandAttempt(serverName string) bool {
	cm.onDemandMu.Lock()
	defer cm.onDemandMu.Unlock()

	if cm.onDemandAttempts == nil {
		cm.onDemandAttempts = make(map[string]*onDemandAttempt)
	}
	attempt, ok := cm.onDemandAttempts[serverName]
	if !ok {
		attempt = &onDemandAttempt{}
		cm.onDemandAttempts[serverName] = attempt
	} else if time.Now().Before(attempt.nextAttempt) {
		return false
	}
	attempt.nextAttempt = time.Now().Add(onDemandBackoff(attempt.failures))
	return true
}

// finishOnDemandAttempt clears the throttle once the host has a certificate of
// its own, and widens the retry window otherwise.
func (cm *CertManager) finishOnDemandAttempt(serverName string) {
	_, rank := cm.findBestCertificate(serverName)

	cm.onDemandMu.Lock()
	defer cm.onDemandMu.Unlock()
	if rank == matchExact {
		delete(cm.onDemandAttempts, serverName)
		return
	}
	if attempt, ok := cm.onDemandAttempts[serverName]; ok {
		attempt.failures++
		attempt.nextAttempt = time.Now().Add(onDemandBackoff(attempt.failures))
	}
}

// onDemandBackoff doubles the wait per consecutive failure, capped so a host
// whose DNS or routing is fixed later is still retried within the hour.
func onDemandBackoff(failures int) time.Duration {
	if failures > 8 {
		failures = 8
	}
	if backoff := onDemandBaseBackoff << failures; backoff < onDemandMaxBackoff {
		return backoff
	}
	return onDemandMaxBackoff
}

// findBestCertificate returns the most specific valid certificate for domain
// across the shared custom certs and every provider, together with its match
// rank. On an equal rank the custom certs win.
func (cm *CertManager) findBestCertificate(domain string) (*CertificateInfo, matchRank) {
	cm.mu.RLock()
	best, bestRank := findBestCertificateIn(cm.customCerts, domain, false)
	cm.mu.RUnlock()

	if bestRank == matchExact {
		return best, bestRank
	}

	for _, p := range cm.providers {
		p.mu.RLock()
		certInfo, rank := findBestCertificateIn(p.certs, domain, false)
		p.mu.RUnlock()
		if rank > bestRank {
			best, bestRank = certInfo, rank
			if bestRank == matchExact {
				break
			}
		}
	}
	return best, bestRank
}

// providerForSNI returns the provider whose allowedHosts claims serverName, or
// nil if no provider claims it (which means no ACME request should be made).
func (cm *CertManager) providerForSNI(serverName string) *provider {
	for _, p := range cm.providers {
		if ok, _ := p.isHostAllowed(serverName); ok {
			return p
		}
	}
	return nil
}

// hasExactCertificate reports whether the provider holds a usable certificate
// that names host explicitly, as opposed to one that only covers it.
func (p *provider) hasExactCertificate(host string, renewal bool) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, rank := findBestCertificateIn(p.certs, host, renewal)
	return rank == matchExact
}

func isCertificateValid(certInfo *CertificateInfo, renewal bool) bool {
	if certInfo == nil || certInfo.Expires.IsZero() {
		return false
	}
	if renewal {
		return time.Until(certInfo.Expires) > renewalBufferTime
	}
	return time.Now().Before(certInfo.Expires)
}

func (cm *CertManager) getDefaultCertificate() (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.defaultCert != nil {
		return cm.defaultCert, nil
	}
	return nil, os.ErrNotExist
}

func (p *provider) checkExistingValidCertificate(domain Domain, renewal bool) *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, host := range domain.Hosts {
		if certInfo, exists := p.certs[host]; exists && isCertificateValid(certInfo, renewal) {
			return certInfo.Certificate
		}
	}
	return nil
}

// findCertificateInfo searches a provider's own cert map for the most specific
// valid match.
func (p *provider) findCertificateInfo(domain string) *CertificateInfo {
	certInfo, _ := findBestCertificateIn(p.certs, domain, false)
	return certInfo
}

// matchRank orders how well a certificate covers a requested host. Higher is
// more specific, and only the highest-ranked certificate is served, so a
// wildcard is used solely when nothing names the host explicitly.
type matchRank int

const (
	matchNone matchRank = iota
	// matchParentKey: cert filed under the parent domain, e.g. "example.com"
	// for "a.example.com". Legacy lookup, kept as a last resort.
	matchParentKey
	// matchWildcardKey: cert filed under "*.<parent>" without listing the
	// pattern among its own domains. Legacy lookup.
	matchWildcardKey
	// matchWildcard: the cert carries a wildcard SAN covering the host.
	matchWildcard
	// matchExact: the cert names the host explicitly.
	matchExact
)

// findBestCertificateIn returns the highest-ranked valid certificate for domain
// in certs. Map iteration order is random, so every entry is scored rather than
// returning the first one that happens to match.
func findBestCertificateIn(certs map[string]*CertificateInfo, domain string, renewal bool) (*CertificateInfo, matchRank) {
	var best *CertificateInfo
	bestRank := matchNone

	consider := func(certInfo *CertificateInfo, rank matchRank) {
		if certInfo == nil || rank <= bestRank || !isCertificateValid(certInfo, renewal) {
			return
		}
		best, bestRank = certInfo, rank
	}

	consider(certs[domain], matchExact)
	if bestRank == matchExact {
		return best, bestRank
	}

	for _, certInfo := range certs {
		consider(certInfo, rankDomainMatch(domain, certInfo))
	}
	if bestRank == matchExact {
		return best, bestRank
	}

	// Legacy key-based fallbacks, for certs whose stored key is not repeated in
	// their own domain list.
	if d := getWildcardDomain(domain); d != "" {
		consider(certs[d], matchWildcardKey)
	}
	if d := getParentDomain(domain); d != "" {
		consider(certs[d], matchParentKey)
	}
	return best, bestRank
}

// rankDomainMatch scores how specifically certInfo covers requestedDomain.
func rankDomainMatch(requestedDomain string, certInfo *CertificateInfo) matchRank {
	rank := matchNone
	for _, certDomain := range certInfo.Domains {
		switch {
		case strings.EqualFold(requestedDomain, certDomain):
			return matchExact
		case matchesWildcardDomain(requestedDomain, certDomain):
			rank = matchWildcard
		}
	}
	return rank
}

// matchesWildcardDomain reports whether the cert pattern is a wildcard covering
// requested. Per RFC 6125 a wildcard stands for exactly one label, so
// "*.example.com" covers "a.example.com" but neither "a.b.example.com" nor the
// bare "example.com".
func matchesWildcardDomain(requested, cert string) bool {
	if !strings.HasPrefix(cert, "*.") {
		return false
	}
	suffix := cert[1:] // ".example.com"
	if len(requested) <= len(suffix) || !strings.EqualFold(requested[len(requested)-len(suffix):], suffix) {
		return false
	}
	label := requested[:len(requested)-len(suffix)]
	return !strings.Contains(label, ".")
}

// normalizeServerName lowercases the SNI value and drops a trailing root dot so
// it compares equal to the names stored on certificates.
func normalizeServerName(serverName string) string {
	return strings.ToLower(strings.TrimSuffix(serverName, "."))
}

func (p *provider) isRequestInProgress(domains []string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inProgressRequests[getRequestKey(domains)]
}

func (p *provider) markRequestInProgress(domains []string, inProgress bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inProgressRequests[getRequestKey(domains)] = inProgress
}

func getRequestKey(domains []string) string {
	sorted := make([]string, len(domains))
	copy(sorted, domains)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

func createCertificateInfoFromACME(cert *tls.Certificate, domains []string, resource *certificate.Resource) *CertificateInfo {
	parsedCert, _ := x509.ParseCertificate(cert.Certificate[0])
	return &CertificateInfo{
		Certificate: cert,
		Domains:     domains,
		Expires:     parsedCert.NotAfter,
		Resource:    resource,
		IssuedAt:    time.Now(),
	}
}

func (p *provider) storeCertificateInfo(domains []string, certInfo *CertificateInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.removeOverlappingCertificates(domains)
	for _, domain := range domains {
		p.certs[domain] = certInfo
	}
}

func (p *provider) removeOverlappingCertificates(newDomains []string) {
	for domain := range p.certs {
		if containsAny(newDomains, p.certs[domain].Domains) {
			delete(p.certs, domain)
		}
	}
}

// AddCertificate adds a single certificate to the shared custom-cert pool. The
// special domain "default" sets the gateway-wide self-signed fallback.
func (cm *CertManager) AddCertificate(domain string, cert *tls.Certificate) {
	if cert == nil {
		return
	}
	certInfo, err := createCertificateInfo(cert)
	if err != nil {
		logger.Error("Error creating certificate info", "error", err)
		return
	}
	cm.addCertificateInfo(domain, certInfo)
}

func (cm *CertManager) addCertificateInfo(domain string, certInfo *CertificateInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if domain == "default" {
		cm.defaultCert = certInfo.Certificate
	} else {
		cm.customCerts[domain] = certInfo
	}
}

// AddCertificates adds multiple certificates to the shared custom-cert pool.
func (cm *CertManager) AddCertificates(certs []tls.Certificate) {
	logger.Debug("Adding certificates to cert-manager", "certs", len(certs))
	for _, cert := range certs {
		commonName, sanNames, err := getCertificateDetails(&cert)
		if err != nil {
			continue
		}
		allDomains := append([]string{commonName}, sanNames...)
		for _, domain := range allDomains {
			if domain != "" {
				cm.AddCertificate(domain, &cert)
			}
		}
	}
	logger.Debug("Certificates added to cert-manager", "count", len(certs))
}

// Certificates returns a merged map of every certificate known to the manager
// (per-provider ACME certs + shared custom certs). For inspection / metrics.
func (cm *CertManager) Certificates() map[string]*CertificateInfo {
	all := make(map[string]*CertificateInfo)
	for _, p := range cm.providers {
		p.mu.RLock()
		for domain, certInfo := range p.certs {
			all[domain] = certInfo
		}
		p.mu.RUnlock()
	}
	cm.mu.RLock()
	for domain, certInfo := range cm.customCerts {
		all[domain] = certInfo
	}
	cm.mu.RUnlock()
	return all
}

func createCertificateInfo(cert *tls.Certificate) (*CertificateInfo, error) {
	commonName, sanNames, err := getCertificateDetails(cert)
	if err != nil {
		return nil, err
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{
		Certificate: cert,
		Domains:     append([]string{commonName}, sanNames...),
		Expires:     parsedCert.NotAfter,
	}, nil
}

func (p *provider) startRenewalService() {
	logger.Info("Starting CertManager renewal service", "provider", p.name)
	if p.cronJob != nil {
		p.cronJob.Stop()
	}
	_, err := p.cronJob.AddFunc(cronExpression, func() {
		logger.Debug("Renewing certificates...", "provider", p.name)
		p.renewCertificates()
	})
	if err != nil {
		logger.Error("Error starting renewal service", "provider", p.name, "error", err)
		return
	}
	p.cronJob.Start()
}

// GenerateCertificate generates a self-signed certificate for the given domain
// and stores it in the shared custom-cert pool.
func (cm *CertManager) GenerateCertificate(domain string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypeRSAPrivateKey,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	cm.AddCertificate(domain, &tlsCert)
	return &tlsCert, nil
}

func (cm *CertManager) GenerateDefaultCertificate() (*tls.Certificate, error) {
	return cm.GenerateCertificate("GOMA DEFAULT CERT")
}

// AcmeInitialized returns true if at least one provider initialized successfully.
func (cm *CertManager) AcmeInitialized() bool {
	for _, p := range cm.providers {
		if p.acmeInitialized {
			return true
		}
	}
	return false
}

// UsesHTTP01Challenge reports whether any configured ACME provider solves the
// HTTP-01 challenge, and therefore whether the gateway needs to proxy
// /.well-known/acme-challenge/ to the local challenge server at all.
func (cm *CertManager) UsesHTTP01Challenge() bool {
	if cm == nil {
		return false
	}
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	for _, p := range cm.providers {
		if p.cfg.Type != CertAcmeProvider {
			continue
		}
		// HTTP-01 is the default when no challenge type is configured.
		if p.cfg.Acme.ChallengeType != DNS01 {
			return true
		}
	}
	return false
}

// HasProvider reports whether a provider with the given name is configured.
func (cm *CertManager) HasProvider(name string) bool {
	if cm == nil {
		return false
	}
	_, ok := cm.providers[name]
	return ok
}

// ProviderNames returns the configured provider names (unsorted).
func (cm *CertManager) ProviderNames() []string {
	names := make([]string, 0, len(cm.providers))
	for n := range cm.providers {
		names = append(names, n)
	}
	return names
}

// DefaultProvider returns the configured default provider name.
func (cm *CertManager) DefaultProvider() string {
	return cm.defaultProvider
}

// isHostAllowed reports which configured route claims host. A route naming the
// host explicitly wins over one that only covers it with a wildcard, so the
// host gets its own certificate rather than inheriting the wildcard route's.
func (p *provider) isHostAllowed(host string) (bool, Domain) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var best Domain
	bestRank := matchNone
	for _, route := range p.allowedHosts {
		for _, pattern := range route.Hosts {
			rank := matchNone
			switch {
			case strings.EqualFold(host, pattern):
				rank = matchExact
			case matchesWildcardDomain(host, pattern):
				rank = matchWildcard
			}
			if rank > bestRank {
				best, bestRank = route, rank
			}
		}
		if bestRank == matchExact {
			return true, best
		}
	}
	return bestRank > matchNone, best
}

// Close stops renewal jobs and persists final state for every provider.
func (cm *CertManager) Close() {
	for _, p := range cm.providers {
		if p.cronJob != nil {
			p.cronJob.Stop()
		}
		if err := p.saveToStorage(); err != nil {
			logger.Error("Error saving final state", "provider", p.name, "error", err)
		}
	}
}

func (p *provider) loadFromStorage() error {
	data, err := os.ReadFile(p.storageFile)
	if err != nil {
		return err
	}

	var storage CertificateStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return fmt.Errorf("failed to unmarshal storage: %w", err)
	}

	if storage.UserAccount != nil {
		user, err := loadUserFromStorage(storage.UserAccount)
		if err != nil {
			return fmt.Errorf("failed to load user account: %w", err)
		}
		p.user = user
	}

	for _, storedCert := range storage.Certificates {
		certInfo, err := loadCertificateFromStorage(storedCert)
		if err != nil {
			logger.Error("Failed to load certificate from storage",
				"provider", p.name, "domain", storedCert.Domain, "error", err)
			continue
		}
		p.certs[storedCert.Domain] = certInfo
	}

	logger.Debug("Loaded data from storage", "provider", p.name, "certificates", len(storage.Certificates))
	return nil
}

func (p *provider) saveToStorage() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	storage := CertificateStorage{
		Version:   configVersion,
		UpdatedAt: time.Now(),
	}

	var err error
	if p.user != nil {
		storage.UserAccount, err = saveUserToStorage(p.user)
		if err != nil {
			return fmt.Errorf("failed to save user account: %w", err)
		}
	}

	saveCertificatesToStorage(&storage, p.certs)

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal storage: %w", err)
	}

	if err = os.WriteFile(p.storageFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write storage file: %w", err)
	}

	logger.Debug("Saved data to storage", "provider", p.name, "certificates", len(storage.Certificates))
	return nil
}

func saveCertificatesToStorage(storage *CertificateStorage, certs map[string]*CertificateInfo) {
	savedDomains := make(map[string]bool)
	for domain, certInfo := range certs {
		alreadySaved := false
		for _, d := range certInfo.Domains {
			if savedDomains[d] {
				alreadySaved = true
				break
			}
		}
		if alreadySaved {
			continue
		}

		storedCert, err := saveCertificateToStorage(domain, certInfo)
		if err != nil {
			logger.Error("Failed to save certificate to storage", "domain", domain, "error", err)
			continue
		}
		storage.Certificates = append(storage.Certificates, storedCert)

		for _, d := range certInfo.Domains {
			savedDomains[d] = true
		}
	}
}

func saveUserToStorage(user *LegoUser) (*StoredUserAccount, error) {
	keyBytes, keyType, err := marshalPrivateKey(user.key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})

	stored := &StoredUserAccount{
		Email:      user.Email,
		PrivateKey: base64.StdEncoding.EncodeToString(keyPEM),
		EabKid:     user.eabKid,
	}

	if user.Registration != nil {
		if err := saveRegistration(user, stored); err != nil {
			logger.Error("Failed to marshal registration", "error", err)
		}
	}

	return stored, nil
}

func marshalPrivateKey(key crypto.PrivateKey) ([]byte, string, error) {
	var keyBytes []byte
	var keyType string
	var err error

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		keyType = pemTypeECPrivateKey
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyType = pemTypeRSAPrivateKey
	default:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		keyType = pemTypePKCS8PrivateKey
	}

	return keyBytes, keyType, err
}

func saveRegistration(user *LegoUser, stored *StoredUserAccount) error {
	regData, err := json.Marshal(user.Registration)
	if err != nil {
		return err
	}
	stored.Registration = base64.StdEncoding.EncodeToString(regData)
	return nil
}

func saveCertificateToStorage(domain string, certInfo *CertificateInfo) (*StoredCertificate, error) {
	if certInfo.Certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	var certPEMBuffer bytes.Buffer
	for _, certDER := range certInfo.Certificate.Certificate {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
		certPEMBuffer.Write(certPEM)
	}

	keyPEM, err := marshalCertificatePrivateKey(certInfo.Certificate.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &StoredCertificate{
		Domain:      domain,
		Certificate: base64.StdEncoding.EncodeToString(certPEMBuffer.Bytes()),
		PrivateKey:  base64.StdEncoding.EncodeToString(keyPEM),
		Domains:     certInfo.Domains,
		Expires:     certInfo.Expires,
		IssuedAt:    certInfo.IssuedAt,
	}, nil
}

func marshalCertificatePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  pemTypeRSAPrivateKey,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  pemTypeECPrivateKey,
			Bytes: keyBytes,
		}), nil
	default:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  pemTypePKCS8PrivateKey,
			Bytes: keyBytes,
		}), nil
	}
}

func loadUserFromStorage(stored *StoredUserAccount) (*LegoUser, error) {
	keyData, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := parsePrivateKey(block)
	if err != nil {
		return nil, err
	}

	user := &LegoUser{
		Email:  stored.Email,
		key:    privateKey,
		eabKid: stored.EabKid,
	}

	if stored.Registration != "" {
		if err := loadRegistration(stored, user); err != nil {
			logger.Error("Failed to load registration", "error", err)
		}
	}

	return user, nil
}

func parsePrivateKey(block *pem.Block) (crypto.PrivateKey, error) {
	switch block.Type {
	case pemTypeECPrivateKey:
		return x509.ParseECPrivateKey(block.Bytes)
	case pemTypeRSAPrivateKey:
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case pemTypePKCS8PrivateKey:
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}

func loadRegistration(stored *StoredUserAccount, user *LegoUser) error {
	regData, err := base64.StdEncoding.DecodeString(stored.Registration)
	if err != nil {
		return fmt.Errorf("failed to decode registration: %w", err)
	}

	var reg registration.Resource
	if err := json.Unmarshal(regData, &reg); err != nil {
		return fmt.Errorf("failed to unmarshal registration: %w", err)
	}

	user.Registration = &reg
	return nil
}

func loadCertificateFromStorage(stored *StoredCertificate) (*CertificateInfo, error) {
	certData, err := base64.StdEncoding.DecodeString(stored.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	keyData, err := base64.StdEncoding.DecodeString(stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &CertificateInfo{
		Certificate: &cert,
		Domains:     stored.Domains,
		Expires:     stored.Expires,
		IssuedAt:    stored.IssuedAt,
	}, nil
}

func getWildcardDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return "*." + strings.Join(parts[1:], ".")
	}
	return ""
}

func getParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[1:], ".")
	}
	return ""
}

func getCertificateDetails(cert *tls.Certificate) (string, []string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", nil, errors.New("no certificate data found")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return parsedCert.Subject.CommonName, parsedCert.DNSNames, nil
}

func containsAny(sliceA, sliceB []string) bool {
	for _, a := range sliceA {
		for _, b := range sliceB {
			if a == b {
				return true
			}
		}
	}
	return false
}
