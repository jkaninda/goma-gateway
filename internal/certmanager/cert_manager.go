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

// Package certmanager provides functionality for managing TLS certificates, including ACME certificates.
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
	"github.com/jkaninda/logger"
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
)

// Domain represents a domain configuration
type Domain struct {
	Name  string
	Hosts []string
}

// Credentials holds authentication credentials for providers

// AcmeConfig holds ACME-specific configuration
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

// CertificateInfo contains certificate information
type CertificateInfo struct {
	Certificate *tls.Certificate
	Domains     []string
	Expires     time.Time
	IssuedAt    time.Time
	Resource    *certificate.Resource
}

// LegoUser implements the lego User interface
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string                        { return u.Email }
func (u *LegoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// CertManager manages TLS certificates including ACME certificates
type CertManager struct {
	mu                 sync.RWMutex
	certs              map[string]*CertificateInfo
	customCerts        map[string]*CertificateInfo
	defaultCert        *tls.Certificate
	legoClient         *lego.Client
	user               *LegoUser
	config             *Config
	storageFile        string
	cacheDir           string
	allowedHosts       []Domain
	renewalTicker      *time.Ticker
	inProgressRequests map[string]bool
	acmeInitialized    bool
}

// NewCertManager creates a new CertManager instance
func NewCertManager(config *Config) (*CertManager, error) {
	storageConfig, err := initializeStorageConfig(config.Acme.StorageFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage configuration: %w", err)
	}

	return &CertManager{
		certs:              make(map[string]*CertificateInfo),
		customCerts:        make(map[string]*CertificateInfo),
		config:             config,
		storageFile:        storageConfig.StorageFile,
		cacheDir:           storageConfig.CacheDir,
		inProgressRequests: make(map[string]bool),
	}, nil
}

// Initialize sets up the certificate manager
func (cm *CertManager) Initialize() error {
	if cm.acmeInitialized {
		logger.Debug("Already initialized")
		return nil // Already initialized
	}
	if err := cm.validateConfig(); err != nil {
		if errors.Is(err, ErrorNoEmail) {
			return err
		}
		logger.Error("Failed to validate Acme config", "error", err)
		return err
	}

	if err := cm.loadFromStorage(); err != nil {
		if err := cm.createNewUser(); err != nil {
			return fmt.Errorf("failed to create new user: %w", err)
		}
	}

	if err := cm.setupLegoClient(); err != nil {
		return fmt.Errorf("failed to setup lego client: %w", err)
	}

	if err := cm.registerUser(); err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	if err := cm.setupChallenges(); err != nil {
		return fmt.Errorf("failed to setup challenges: %w", err)
	}
	cm.acmeInitialized = true
	return nil
}

// validateConfig validates the configuration
func (cm *CertManager) validateConfig() error {
	if cm.config == nil || cm.config.Acme.Email == "" {
		return ErrorNoEmail
	}
	if cm.config.Provider == CertVaultProvider {
		return errors.New("vault provider not yet implemented")
	}
	if cm.config.Acme.ChallengeType == DNS01 {
		if cm.config.Acme.DnsProvider == "" && cm.config.Acme.Credentials.ApiToken == "" {
			return errors.New("no DNS provider or API token configured for DNS01 challenge")
		}
	}
	return nil
}

// User Management
func (cm *CertManager) createNewUser() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	cm.user = &LegoUser{
		Email: cm.config.Acme.Email,
		key:   privateKey,
	}
	return nil
}

func (cm *CertManager) registerUser() error {
	if cm.user.Registration != nil {
		return nil
	}

	reg, err := cm.legoClient.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	cm.user.Registration = reg
	return cm.saveToStorage()
}

// setupLegoClient sets up the ACME client using the lego library
func (cm *CertManager) setupLegoClient() error {
	config := lego.NewConfig(cm.user)
	config.Certificate.KeyType = certcrypto.RSA2048

	if cm.config.Acme.DirectoryURL != "" {
		config.CADirURL = cm.config.Acme.DirectoryURL
		cm.configureInsecureClientIfNeeded(config)
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	cm.legoClient = client
	return nil
}

func (cm *CertManager) configureInsecureClientIfNeeded(config *lego.Config) {
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

// Challenge Setup
func (cm *CertManager) setupChallenges() error {
	if cm.config.Acme.ChallengeType == DNS01 {
		provider, err := cm.createDNSProvider()
		if err != nil {
			return fmt.Errorf("failed to create DNS provider: %w", err)
		}
		return cm.legoClient.Challenge.SetDNS01Provider(provider)
	}

	// Default to HTTP01
	return cm.legoClient.Challenge.SetHTTP01Provider(
		http01.NewProviderServer("", httpChallengePort),
	)
}

func (cm *CertManager) createDNSProvider() (challenge.Provider, error) {
	switch cm.config.Acme.DnsProvider {
	case cloudflareProvider:
		if cm.config.Acme.Credentials.ApiToken == "" {
			return nil, errors.New("cloudflare API token is required")
		}
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthToken = cm.config.Acme.Credentials.ApiToken
		return cloudflare.NewDNSProviderConfig(cfg)
	case route53Provider:
		return nil, errors.New("route53 provider not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", cm.config.Acme.DnsProvider)
	}
}

// AutoCert starts the automatic certificate management process
func (cm *CertManager) AutoCert(domains []Domain) {
	cm.mu.Lock()
	cm.allowedHosts = domains
	cm.mu.Unlock()

	cm.startRenewalService()
	if err := cm.processCertificates(); err != nil {
		logger.Error("Error processing certificates", "error", err)
	}
	logger.Debug("AutoCert process started", "domains", len(domains))
}
func (cm *CertManager) UpdateDomains(domains []Domain) {
	if !cm.acmeInitialized {
		logger.Debug("ACME client not initialized, skipping domain update")
		return
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.allowedHosts = domains
	logger.Debug("Updated allowed hosts", "count", len(cm.allowedHosts))
	logger.Debug("Resetting in-progress requests due to domain update")

	// Start processing certificates immediately
	go func() {
		if err := cm.processCertificates(); err != nil {
			logger.Error("Error processing certificates after domain update", "error", err)
		}
	}()

}

func (cm *CertManager) processCertificates() error {
	stats := &ProcessingStats{}
	var wg sync.WaitGroup

	for _, domain := range cm.allowedHosts {
		if cm.shouldSkipDomain(domain, stats, false) {
			continue
		}

		wg.Add(1)
		go func(d Domain) {
			defer wg.Done()
			if err := cm.processDomain(d, stats, false); err != nil {
				time.Sleep(errorDelay)
				return
			}
			time.Sleep(requestDelay)
		}(domain)
	}

	wg.Wait()
	logger.Debug("Processing complete", "success", stats.Success, "errors", stats.Errors, "skipped", stats.Skipped)
	return cm.validateProcessingResults(stats)
}

func (cm *CertManager) requestNewCertificate(host string, stats *ProcessingStats, renewal bool) error {
	if stats == nil {
		stats = &ProcessingStats{}
	}

	logger.Debug("=== requestNewCertificate called ===", "host", host)
	cm.mu.RLock()
	logger.Debug("Current allowed hosts", "count", len(cm.allowedHosts))
	logger.Debug("Requesting new certificate", "domain", host, "hosts_count", len(cm.allowedHosts))
	cm.mu.RUnlock()

	allowed, domain := cm.isHostAllowed(host)
	logger.Debug("isHostAllowed", "allowed", allowed, "host", host, "domain", domain)
	if !allowed {
		stats.Skipped++
		logger.Debug("Skipping certificate request, domain not recognized", "host", host)
		return nil
	}
	if cm.shouldSkipDomain(domain, stats, renewal) {
		stats.Skipped++
		return nil
	}
	key := cm.getRequestKey(domain.Hosts)
	inProgress := cm.isRequestInProgress(domain.Hosts)
	logger.Debug("Request state", "inProgress", inProgress, "requestKey", key)

	if err := cm.processDomain(domain, stats, renewal); err != nil {
		if !errors.Is(err, ErrAlreadyInProgress) {
			logger.Error("Failed to process domain", "domain", domain.Hosts[0], "error", err)
			time.Sleep(errorDelay)
			return err
		}
		logger.Debug("Certificate request already in progress", "host", host, "route", domain.Name, "hosts", domain.Hosts)
		return nil

	}
	stats.Success++
	time.Sleep(requestDelay)
	return nil
}

func (cm *CertManager) shouldSkipDomain(domain Domain, stats *ProcessingStats, renewal bool) bool {
	if len(domain.Hosts) == 0 {
		stats.Skipped++
		return true
	}
	if cm.getExistingValidCertificate(domain.Hosts[0], renewal) != nil {
		stats.Skipped++
		return true
	}
	if cm.isRequestInProgress(domain.Hosts) {
		stats.Skipped++
		return true
	}
	return false
}

func (cm *CertManager) processDomain(domain Domain, stats *ProcessingStats, renewal bool) error {
	logger.Debug("Processing domain", "domain", domain.Name, "hosts", domain.Hosts)
	cert, err := cm.requestCertificateSync(domain, renewal)
	if err != nil {
		logger.Error("Failed to process domain", "domain", domain.Name, "error", err)
		stats.Errors++
		return err
	}
	if cert != nil {
		logger.Debug("Certificate obtained for domain", "domain", domain.Name, "hosts", domain.Hosts)
		stats.Success++
	}
	return nil
}

func (cm *CertManager) validateProcessingResults(stats *ProcessingStats) error {
	if stats.Errors > 0 && stats.Success == 0 {
		return fmt.Errorf("all certificate requests failed (%d errors)", stats.Errors)
	}
	return nil
}

func (cm *CertManager) renewCertificates() {
	certsToRenew := cm.getCertificatesToRenew()
	stats := &ProcessingStats{}

	logger.Info("Renewing certificates", "count", len(certsToRenew))
	for _, host := range certsToRenew {
		err := cm.requestNewCertificate(host, stats, true)
		if err != nil {
			logger.Error("Error renewing certificate", "host", host, "error", err)
			continue
		}
		time.Sleep(requestDelay)
	}
	logger.Info("Certificate renewal complete", "success", stats.Success, "errors", stats.Errors, "skipped", stats.Skipped)
}
func (cm *CertManager) getCertificatesToRenew() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var certsToRenew []string
	for domain, certInfo := range cm.certs {
		logger.Debug("Checking certificate for renewal", "domain", domain, " IssuedAt", certInfo.IssuedAt, "expires", certInfo.Expires, "time_left", time.Until(certInfo.Expires))
		if time.Until(certInfo.Expires) <= renewalBufferTime {
			certsToRenew = append(certsToRenew, domain)
		}
	}
	return certsToRenew
}

// Certificate Request
func (cm *CertManager) requestCertificateSync(domain Domain, renewal bool) (*tls.Certificate, error) {
	if !cm.acmeInitialized {
		return nil, errors.New("ACME client not initialized")
	}

	if cert := cm.checkExistingValidCertificate(domain, renewal); cert != nil {
		return cert, nil
	}

	if cm.isRequestInProgress(domain.Hosts) {
		return nil, fmt.Errorf("certificate request already in progress for domains: %v", domain.Hosts)
	}

	return cm.performCertificateRequest(domain)
}

func (cm *CertManager) performCertificateRequest(domain Domain) (*tls.Certificate, error) {
	httpChallengeMu.Lock()
	defer httpChallengeMu.Unlock()

	cm.markRequestInProgress(domain.Hosts, true)
	defer cm.markRequestInProgress(domain.Hosts, false)
	certificates, err := cm.legoClient.Certificate.Obtain(certificate.ObtainRequest{
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

	certInfo := cm.createCertificateInfoFromACME(&cert, domain.Hosts, certificates)
	cm.storeCertificateInfo(domain.Hosts, certInfo)

	if err = cm.saveToStorage(); err != nil {
		logger.Error("Failed to save certificate to storage", "error", err)
	}
	return &cert, nil
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := hello.ServerName

	if len(cm.certs) == 0 && cm.customCerts == nil || len(serverName) == 0 {
		logger.Debug("No certificates available, returning default certificate")
		return cm.getDefaultCertificate()
	}

	if cert := cm.getExistingValidCertificate(serverName, false); cert != nil {
		return cert, nil
	}
	logger.Debug("Certificate not found or invalid", "server_name", serverName)
	go func() {
		if err := cm.requestNewCertificate(serverName, nil, false); err != nil {
			logger.Error("Background certificate processing failed", "error", err)
		}
	}()
	logger.Debug("Returning default certificate for server name", "server_name", serverName)
	return cm.getDefaultCertificate()
}

func (cm *CertManager) getExistingValidCertificate(serverName string, renewal bool) *tls.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	certInfo := cm.findCertificateInfo(serverName)
	if certInfo != nil && cm.isCertificateValid(certInfo, renewal) {
		logger.Debug("Certificate found for server", "server_name", serverName)
		return certInfo.Certificate
	}

	logger.Debug("Certificate not found or invalid", "server_name", serverName)
	return nil
}

func (cm *CertManager) isCertificateValid(certInfo *CertificateInfo, renewal bool) bool {
	if certInfo == nil || certInfo.Expires.IsZero() {
		return false
	}
	if renewal {
		return time.Until(certInfo.Expires) > renewalBufferTime
	}
	// Standard validity: not expired
	return time.Now().Before(certInfo.Expires)
}

func (cm *CertManager) getDefaultCertificate() (*tls.Certificate, error) {
	if cm.defaultCert != nil {
		return cm.defaultCert, nil
	}
	return nil, os.ErrNotExist
}

// Certificate Management Helpers
func (cm *CertManager) checkExistingValidCertificate(domain Domain, renewal bool) *tls.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, host := range domain.Hosts {
		if certInfo, exists := cm.certs[host]; exists && cm.isCertificateValid(certInfo, renewal) {
			return certInfo.Certificate
		}
	}
	return nil
}

func (cm *CertManager) findCertificateInfo(domain string) *CertificateInfo {
	// Check exact matches first
	if certInfo := cm.findExactMatch(domain); certInfo != nil {
		return certInfo
	}

	// Check domain matches in certificate SAN lists
	if certInfo := cm.findDomainMatch(domain); certInfo != nil {
		return certInfo
	}

	// Check wildcard and parent domain matches
	return cm.findWildcardMatch(domain)
}

func (cm *CertManager) findExactMatch(domain string) *CertificateInfo {
	if certInfo, exists := cm.certs[domain]; exists {
		return certInfo
	}
	if certInfo, exists := cm.customCerts[domain]; exists {
		return certInfo
	}
	return nil
}

func (cm *CertManager) findDomainMatch(domain string) *CertificateInfo {
	for _, certInfo := range cm.certs {
		if cm.domainMatchesCertificate(domain, certInfo) {
			return certInfo
		}
	}
	for _, certInfo := range cm.customCerts {
		if cm.domainMatchesCertificate(domain, certInfo) {
			return certInfo
		}
	}
	return nil
}

func (cm *CertManager) findWildcardMatch(domain string) *CertificateInfo {
	wildcardDomains := []string{getWildcardDomain(domain), getParentDomain(domain)}

	for _, d := range wildcardDomains {
		if d == "" {
			continue
		}
		if certInfo, exists := cm.certs[d]; exists {
			return certInfo
		}
		if certInfo, exists := cm.customCerts[d]; exists {
			return certInfo
		}
	}
	return nil
}

func (cm *CertManager) domainMatchesCertificate(requestedDomain string, certInfo *CertificateInfo) bool {
	for _, certDomain := range certInfo.Domains {
		if cm.matchesDomain(requestedDomain, certDomain) {
			return true
		}
	}
	return false
}

func (cm *CertManager) matchesDomain(requested, cert string) bool {
	if requested == cert {
		return true
	}

	if strings.HasPrefix(cert, "*.") {
		wildcardBase := cert[2:]
		return strings.HasSuffix(requested, "."+wildcardBase) || requested == wildcardBase
	}

	return false
}

// Request Progress Tracking
func (cm *CertManager) isRequestInProgress(domains []string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.inProgressRequests[cm.getRequestKey(domains)]
}

func (cm *CertManager) markRequestInProgress(domains []string, inProgress bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.inProgressRequests[cm.getRequestKey(domains)] = inProgress
}

func (cm *CertManager) getRequestKey(domains []string) string {
	sorted := make([]string, len(domains))
	copy(sorted, domains)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}

// Certificate Storage and Info Management
func (cm *CertManager) createCertificateInfoFromACME(cert *tls.Certificate, domains []string, resource *certificate.Resource) *CertificateInfo {
	parsedCert, _ := x509.ParseCertificate(cert.Certificate[0])
	return &CertificateInfo{
		Certificate: cert,
		Domains:     domains,
		Expires:     parsedCert.NotAfter,
		Resource:    resource,
		IssuedAt:    time.Now(),
	}
}

func (cm *CertManager) storeCertificateInfo(domains []string, certInfo *CertificateInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.removeOverlappingCertificates(domains)

	for _, domain := range domains {
		cm.certs[domain] = certInfo
	}
}

func (cm *CertManager) removeOverlappingCertificates(newDomains []string) {
	for domain := range cm.certs {
		if containsAny(newDomains, cm.certs[domain].Domains) {
			delete(cm.certs, domain)
		}
	}
}

// AddCertificate adds a single certificate to the CertManager
func (cm *CertManager) AddCertificate(domain string, cert tls.Certificate) {
	certInfo, err := cm.createCertificateInfo(&cert)
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

// AddCertificates adds multiple certificates to the CertManager
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
				cm.AddCertificate(domain, cert)
			}
		}
	}
	logger.Debug("Certificates added to cert-manager", "count", len(certs))
}

// Certificates returns all certificates managed by the CertManager
func (cm *CertManager) Certificates() map[string]*CertificateInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	allCerts := make(map[string]*CertificateInfo)

	for domain, certInfo := range cm.certs {
		allCerts[domain] = certInfo
	}
	for domain, certInfo := range cm.customCerts {
		allCerts[domain] = certInfo
	}

	return allCerts
}

func (cm *CertManager) createCertificateInfo(cert *tls.Certificate) (*CertificateInfo, error) {
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

// Renewal Service
func (cm *CertManager) startRenewalService() {
	logger.Debug("Starting renewal service")
	if cm.renewalTicker != nil {
		logger.Debug("Stopping existing renewal ticker")
		cm.renewalTicker.Stop()
	}

	cm.renewalTicker = time.NewTicker(renewalCheckInterval)
	go func() {
		for range cm.renewalTicker.C {
			logger.Debug("Renewing certificates...")
			cm.renewCertificates()
		}
	}()
}

// GenerateCertificate generates a self-signed certificate for the given domain
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

	cm.AddCertificate(domain, tlsCert)
	return &tlsCert, nil
}

func (cm *CertManager) GenerateDefaultCertificate() (*tls.Certificate, error) {
	return cm.GenerateCertificate("GOMA DEFAULT CERT")
}

func (cm *CertManager) AcmeInitialized() bool {
	return cm.acmeInitialized
}
func (cm *CertManager) isHostAllowed(host string) (bool, Domain) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if len(cm.allowedHosts) == 0 {
		logger.Debug("No allowed hosts configured, returning false for host", "host", host)
		return false, Domain{}
	}
	for _, route := range cm.allowedHosts {
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

func (cm *CertManager) Close() {
	if cm.renewalTicker != nil {
		cm.renewalTicker.Stop()
	}

	if err := cm.saveToStorage(); err != nil {
		logger.Error("Error saving final state", "error", err)
	}
}

// Storage Operations - these would need to be implemented based on your storage requirements
func (cm *CertManager) loadFromStorage() error {
	data, err := os.ReadFile(cm.storageFile)
	if err != nil {
		return err
	}

	var storage CertificateStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return fmt.Errorf("failed to unmarshal storage: %w", err)
	}

	if storage.UserAccount != nil {
		user, err := cm.loadUserFromStorage(storage.UserAccount)
		if err != nil {
			return fmt.Errorf("failed to load user account: %w", err)
		}
		cm.user = user
	}

	for _, storedCert := range storage.Certificates {
		certInfo, err := cm.loadCertificateFromStorage(storedCert)
		if err != nil {
			logger.Error("Failed to load certificate from storage",
				"domain", storedCert.Domain, "error", err)
			continue
		}

		cm.certs[storedCert.Domain] = certInfo

	}

	logger.Debug("Loaded data from storage", "certificates", len(storage.Certificates))
	return nil

}

func (cm *CertManager) saveToStorage() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	storage := CertificateStorage{
		Version:   configVersion,
		UpdatedAt: time.Now(),
	}

	var err error
	if cm.user != nil {
		storage.UserAccount, err = cm.saveUserToStorage(cm.user)
		if err != nil {
			return fmt.Errorf("failed to save user account: %w", err)
		}
	}

	// Save certificate
	cm.saveCertificatesToStorage(&storage)

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal storage: %w", err)
	}

	if err = os.WriteFile(cm.storageFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write storage file: %w", err)
	}

	logger.Debug("Saved data to storage", "certificates", len(storage.Certificates))
	return nil
}

func (cm *CertManager) saveCertificatesToStorage(storage *CertificateStorage) {
	savedDomains := make(map[string]bool)
	for domain, certInfo := range cm.certs {
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

		storedCert, err := cm.saveCertificateToStorage(domain, certInfo)
		if err != nil {
			logger.Error("Failed to save certificate to storage",
				"domain", domain, "error", err)
			continue
		}
		storage.Certificates = append(storage.Certificates, storedCert)

		// Mark all domains in this cert as saved
		for _, d := range certInfo.Domains {
			savedDomains[d] = true
		}
	}

}

func (cm *CertManager) saveUserToStorage(user *LegoUser) (*StoredUserAccount, error) {
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
		if err := cm.saveRegistration(user, stored); err != nil {
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

func (cm *CertManager) saveRegistration(user *LegoUser, stored *StoredUserAccount) error {
	regData, err := json.Marshal(user.Registration)
	if err != nil {
		return err
	}
	stored.Registration = base64.StdEncoding.EncodeToString(regData)
	return nil
}

func (cm *CertManager) saveCertificateToStorage(domain string, certInfo *CertificateInfo) (*StoredCertificate, error) {
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
func (cm *CertManager) loadUserFromStorage(stored *StoredUserAccount) (*LegoUser, error) {
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
		if err := cm.loadRegistration(stored, user); err != nil {
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

func (cm *CertManager) loadRegistration(stored *StoredUserAccount, user *LegoUser) error {
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

func (cm *CertManager) loadCertificateFromStorage(stored *StoredCertificate) (*CertificateInfo, error) {
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
