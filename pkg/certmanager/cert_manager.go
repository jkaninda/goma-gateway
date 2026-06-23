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
	storageConfig, err := initializeProviderStorageConfig(name, cfg.Acme.StorageFile)
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

	if err := p.loadFromStorage(); err != nil {
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
	if p.cfg.Acme.Email == "" {
		return ErrorNoEmail
	}
	if p.cfg.Type == CertVaultProvider {
		return errors.New("vault provider not yet implemented")
	}
	if p.cfg.Acme.ChallengeType == DNS01 {
		if p.cfg.Acme.DnsProvider == "" && p.cfg.Acme.Credentials.ApiToken == "" {
			return errors.New("no DNS provider or API token configured for DNS01 challenge")
		}
	}
	return nil
}

func (p *provider) createNewUser() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	p.user = &LegoUser{
		Email: p.cfg.Acme.Email,
		key:   privateKey,
	}
	return nil
}

func (p *provider) registerUser() error {
	if p.user.Registration != nil {
		return nil
	}
	reg, err := p.legoClient.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}
	p.user.Registration = reg
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

	p.legoClient = client
	return nil
}

func (p *provider) configureInsecureClientIfNeeded(config *lego.Config) {
	env := os.Getenv(gomaEnv)
	if env == development || env == local {
		config.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
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
		http01.NewProviderServer("", httpChallengePort),
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
		if p.shouldSkipDomain(domain, stats, false) {
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
	if p.shouldSkipDomain(domain, stats, renewal) {
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

func (p *provider) shouldSkipDomain(domain Domain, stats *ProcessingStats, renewal bool) bool {
	if len(domain.Hosts) == 0 {
		stats.Skipped++
		return true
	}
	if p.getExistingValidCertificate(domain.Hosts[0], renewal) != nil {
		stats.Skipped++
		return true
	}
	if p.isRequestInProgress(domain.Hosts) {
		stats.Skipped++
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

// GetCertificate is the TLS GetCertificate callback. It walks shared customCerts,
// then each provider's certs, and finally falls back to the default cert.
// If no provider claims the SNI, no ACME request is made.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := hello.ServerName
	if serverName == "" {
		return cm.getDefaultCertificate()
	}

	if certInfo := cm.findCustomCert(serverName); certInfo != nil && isCertificateValid(certInfo, false) {
		return certInfo.Certificate, nil
	}

	for _, p := range cm.providers {
		if certInfo := p.findCertificateInfo(serverName); certInfo != nil && isCertificateValid(certInfo, false) {
			return certInfo.Certificate, nil
		}
	}

	if owner := cm.providerForSNI(serverName); owner != nil {
		go func() {
			if err := owner.requestNewCertificate(serverName, nil, false); err != nil {
				logger.Error("Background certificate processing failed", "provider", owner.name, "error", err)
			}
		}()
	} else {
		logger.Debug("No provider claims SNI, returning default certificate", "server_name", serverName)
	}

	return cm.getDefaultCertificate()
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

func (p *provider) getExistingValidCertificate(serverName string, renewal bool) *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	certInfo := p.findCertificateInfo(serverName)
	if certInfo != nil && isCertificateValid(certInfo, renewal) {
		return certInfo.Certificate
	}
	return nil
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

// findCertificateInfo searches a provider's own cert map for a match (exact,
// SAN list, then wildcard / parent domain).
func (p *provider) findCertificateInfo(domain string) *CertificateInfo {
	if certInfo, exists := p.certs[domain]; exists {
		return certInfo
	}
	for _, certInfo := range p.certs {
		if domainMatchesCertificate(domain, certInfo) {
			return certInfo
		}
	}
	for _, d := range []string{getWildcardDomain(domain), getParentDomain(domain)} {
		if d == "" {
			continue
		}
		if certInfo, exists := p.certs[d]; exists {
			return certInfo
		}
	}
	return nil
}

// findCustomCert searches the shared customCerts map (route-level / file-loaded
// certificates that are not provider-bound).
func (cm *CertManager) findCustomCert(domain string) *CertificateInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if certInfo, exists := cm.customCerts[domain]; exists {
		return certInfo
	}
	for _, certInfo := range cm.customCerts {
		if domainMatchesCertificate(domain, certInfo) {
			return certInfo
		}
	}
	for _, d := range []string{getWildcardDomain(domain), getParentDomain(domain)} {
		if d == "" {
			continue
		}
		if certInfo, exists := cm.customCerts[d]; exists {
			return certInfo
		}
	}
	return nil
}

func domainMatchesCertificate(requestedDomain string, certInfo *CertificateInfo) bool {
	for _, certDomain := range certInfo.Domains {
		if matchesDomain(requestedDomain, certDomain) {
			return true
		}
	}
	return false
}

func matchesDomain(requested, cert string) bool {
	if requested == cert {
		return true
	}
	if strings.HasPrefix(cert, "*.") {
		wildcardBase := cert[2:]
		return strings.HasSuffix(requested, "."+wildcardBase) || requested == wildcardBase
	}
	return false
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
		Type:  "RSA PRIVATE KEY",
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

func (p *provider) isHostAllowed(host string) (bool, Domain) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.allowedHosts) == 0 {
		return false, Domain{}
	}
	for _, route := range p.allowedHosts {
		for _, pattern := range route.Hosts {
			if strings.EqualFold(host, pattern) {
				return true, route
			}
			if strings.HasPrefix(pattern, "*.") {
				suffix := pattern[1:]
				if strings.HasSuffix(host, suffix) {
					return true, route
				}
			}
		}
	}
	return false, Domain{}
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
		keyType = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyType = "RSA PRIVATE KEY"
	default:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
		keyType = "PRIVATE KEY"
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
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}), nil
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}), nil
	default:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
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
		Email: stored.Email,
		key:   privateKey,
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
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
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
