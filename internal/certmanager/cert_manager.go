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

package certmanager

import (
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
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/jkaninda/logger"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Storage types
type (
	StoredUserAccount struct {
		Email        string `json:"email"`
		PrivateKey   string `json:"private_key"`  // base64 encoded
		Registration string `json:"registration"` // base64 encoded JSON
	}

	StoredCertificate struct {
		Domain      string    `json:"domain"`
		Certificate string    `json:"certificate"` // base64 encoded PEM
		PrivateKey  string    `json:"private_key"` // base64 encoded PEM
		Domains     []string  `json:"domains"`
		Expires     time.Time `json:"expires"`
		IssuedAt    time.Time `json:"issued_at"`
		IsDefault   bool      `json:"is_default"`
	}

	CertificateStorage struct {
		UserAccount  *StoredUserAccount   `json:"user_account"`
		Certificates []*StoredCertificate `json:"certificates"`
		Version      string               `json:"version"`
		UpdatedAt    time.Time            `json:"updated_at"`
	}
)

type (
	RouteHost struct {
		Name  string
		Hosts []string
	}
)

type (
	LegoUser struct {
		Email        string
		Registration *registration.Resource
		key          crypto.PrivateKey
	}
)

func (u *LegoUser) GetEmail() string                        { return u.Email }
func (u *LegoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type (
	CertificateInfo struct {
		Certificate *tls.Certificate
		Domains     []string
		Expires     time.Time
		Resource    *certificate.Resource
	}
)

// CertManager manages TLS certificates including ACME (Let's Encrypt) certificates
type CertManager struct {
	mu                 sync.RWMutex
	certs              map[string]*CertificateInfo
	customCerts        map[string]*CertificateInfo
	defaultCert        *tls.Certificate
	legoClient         *lego.Client
	user               *LegoUser
	cacheDir           string
	storageFile        string
	email              string
	allowedHosts       []RouteHost
	renewalTicker      *time.Ticker
	httpChallenge      bool
	acme               *Acme
	inProgressRequests map[string]bool
}

// NewCertManager creates a new CertManager instance
func NewCertManager(acme Acme) (*CertManager, error) {
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}
	if acme.Storage != "" {
		acmeFile = acme.Storage
	}
	cm := &CertManager{
		certs:         make(map[string]*CertificateInfo),
		customCerts:   make(map[string]*CertificateInfo),
		cacheDir:      cacheDir,
		storageFile:   filepath.Join(cacheDir, acmeFile),
		email:         acme.Email,
		acme:          &acme,
		httpChallenge: true,
	}
	if acme.Email == "" {
		cm.httpChallenge = false
		return cm, nil
	}
	if err := cm.initialize(); err != nil {
		return nil, err
	}

	return cm, nil
}

func (cm *CertManager) initialize() error {
	if err := cm.loadFromStorage(); err != nil {
		logger.Debug("No existing storage found, creating new user", "error", err)
		if err = cm.createNewUser(); err != nil {
			return fmt.Errorf("failed to create new user: %w", err)
		}
	}
	if cm.acme.Challenge.Type == DNS01 {
		if cm.acme.Challenge.Provider == "" && cm.acme.Challenge.Credentials.ApiToken == "" {
			return fmt.Errorf("no challenge provider or api token provided")
		}
	}
	if err := cm.setupLegoClient(); err != nil {
		return fmt.Errorf("failed to setup ACME client: %w", err)
	}

	if err := cm.registerUser(); err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	if err := cm.setupChallenges(); err != nil {
		return fmt.Errorf("failed to setup HTTP challenge: %w", err)
	}
	return nil

}

func (cm *CertManager) setupLegoClient() error {
	config := lego.NewConfig(cm.user)
	config.Certificate.KeyType = certcrypto.RSA2048
	if cm.acme.DirectoryURL != "" {
		config.CADirURL = cm.acme.DirectoryURL
	}
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}
	cm.legoClient = client
	return nil
}

// User management
func (cm *CertManager) createNewUser() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	cm.user = &LegoUser{
		Email: cm.email,
		key:   privateKey,
	}
	return nil
}

// Storage operations
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

		if storedCert.IsDefault {
			cm.defaultCert = certInfo.Certificate
		} else {
			cm.certs[storedCert.Domain] = certInfo
		}
	}

	logger.Debug("Loaded data from storage", "certificates", len(storage.Certificates))
	return nil
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
	}, nil
}

func (cm *CertManager) saveToStorage() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	storage := CertificateStorage{
		Version:   "1.0",
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

	// First process all certificates
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

		storedCert, err := cm.saveCertificateToStorage(domain, certInfo, false)
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

func (cm *CertManager) saveCertificateToStorage(domain string, certInfo *CertificateInfo, isDefault bool) (*StoredCertificate, error) {
	if certInfo.Certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certInfo.Certificate.Certificate[0],
	})

	keyPEM, err := marshalCertificatePrivateKey(certInfo.Certificate.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &StoredCertificate{
		Domain:      domain,
		Certificate: base64.StdEncoding.EncodeToString(certPEM),
		PrivateKey:  base64.StdEncoding.EncodeToString(keyPEM),
		Domains:     certInfo.Domains,
		Expires:     certInfo.Expires,
		IssuedAt:    time.Now(),
		IsDefault:   isDefault,
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

// ACME operations
func (cm *CertManager) registerUser() error {
	if cm.user.Registration != nil {
		logger.Debug("User already registered")
		return nil
	}

	reg, err := cm.legoClient.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return fmt.Errorf("failed to register user: %w", err)
	}

	cm.user.Registration = reg
	logger.Debug("User registered with ACME provider", "email", cm.email)

	if err := cm.saveToStorage(); err != nil {
		logger.Error("Failed to save user registration to storage", "error", err)
	}
	return nil
}

func (cm *CertManager) setupChallenges() error {
	// Handle DNS challenge if configured
	if cm.acme.Challenge.Type == DNS01 {
		provider, err := cm.createDNSProvider()
		if err != nil {
			return fmt.Errorf("failed to create DNS provider: %w", err)
		}
		logger.Debug("Challenges enabled", "provider", provider)
		return cm.legoClient.Challenge.SetDNS01Provider(provider)
	}
	// Handle HTTP challenge if configured
	if cm.httpChallenge {
		logger.Debug("Challenges enabled, using HTTP01")
		return cm.legoClient.Challenge.SetHTTP01Provider(http01.NewProviderServer("", httpChallengePort))

	}

	return nil
}

func (cm *CertManager) createDNSProvider() (challenge.Provider, error) {
	switch cm.acme.Challenge.Provider {
	case cloudflareProvider:
		credentials := cm.acme.Challenge.Credentials
		if credentials.ApiToken == "" {
			return nil, errors.New("cloudflare API token is required")
		}
		cfg := cloudflare.NewDefaultConfig()
		cfg.AuthToken = credentials.ApiToken
		return cloudflare.NewDNSProviderConfig(cfg)
	case Route53Provider:
		return nil, errors.New("route53 provider not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", cm.acme.Challenge.Provider)
	}
}

// Certificate management
func (cm *CertManager) AutoCert(hosts []RouteHost) {
	cm.mu.Lock()
	cm.allowedHosts = hosts
	cm.mu.Unlock()

	cm.startRenewalService()
	logger.Debug("AutoCert configured", "hosts", hosts)
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

func (cm *CertManager) AddCertificate(domain string, cert tls.Certificate) {
	certInfo, err := cm.createCertificateInfo(&cert)
	if err != nil {
		logger.Error("Failed to get certificate details", "error", err)
		return
	}

	cm.AddCertificateInfo(domain, certInfo)
}
func (cm *CertManager) AddCertificateInfo(domain string, certInfo *CertificateInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if domain == "default" {
		cm.defaultCert = certInfo.Certificate
	} else {
		cm.customCerts[domain] = certInfo
	}
}

func (cm *CertManager) AddCertificates(certs []tls.Certificate) {
	for _, cert := range certs {
		commonName, sanNames, err := getCertificateDetails(&cert)
		if err != nil {
			continue
		}
		for _, domain := range append([]string{commonName}, sanNames...) {
			if domain != "" {
				cm.AddCertificate(domain, cert)
			}
		}
	}
}

func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := hello.ServerName

	if cert := cm.getExistingValidCertificate(serverName); cert != nil {
		return cert, nil
	}
	// Kick off ACME request in background
	go cm.tryACME(serverName)

	// Return default certificate immediately
	return cm.getDefaultCertificate(serverName)
}

func (cm *CertManager) getExistingValidCertificate(serverName string) *tls.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	certInfo := cm.findCertificateInfo(serverName)
	if certInfo != nil && time.Until(certInfo.Expires) > 24*time.Hour {
		logger.Debug("Serving certificate", "server_name", serverName, "type", "manual")
		return certInfo.Certificate
	}
	return nil
}

func (cm *CertManager) tryACME(serverName string) *tls.Certificate {
	if allowed, routeHost := cm.isHostAllowed(serverName); allowed {
		cert, err := cm.obtainCertificate(routeHost)
		if err == nil {
			logger.Debug("Serving certificate", "server_name", serverName, "type", "acme")
			return cert
		}
		logger.Error("ACME certificate acquisition failed",
			"server_name", serverName,
			"error", err.Error(),
		)
	}
	return nil
}

func (cm *CertManager) getDefaultCertificate(serverName string) (*tls.Certificate, error) {
	if cm.defaultCert != nil {
		logger.Debug("Serving default certificate", "server_name", serverName, "type", "default")
		return cm.defaultCert, nil
	}

	logger.Debug("No matching certificate found", "server_name", serverName)
	return nil, os.ErrNotExist
}

func (cm *CertManager) isHostAllowed(host string) (bool, RouteHost) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

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
	return false, RouteHost{}
}

func (cm *CertManager) obtainCertificate(routeHost RouteHost) (*tls.Certificate, error) {
	if cert := cm.checkExistingValidCertificate(routeHost); cert != nil {
		return cert, nil
	}

	return cm.requestNewCertificate(routeHost)
}

func (cm *CertManager) checkExistingValidCertificate(routeHost RouteHost) *tls.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, domain := range routeHost.Hosts {
		if certInfo, exists := cm.certs[domain]; exists {
			if time.Until(certInfo.Expires) > 24*time.Hour {
				return certInfo.Certificate
			}
		}
	}
	return nil
}

func (cm *CertManager) requestNewCertificate(routeHost RouteHost) (*tls.Certificate, error) {
	// Check if another request is already in progress for these domains
	if cm.isRequestInProgress(routeHost.Hosts) {
		return nil, fmt.Errorf("certificate request already in progress for domains: %v", routeHost.Hosts)
	}

	// Mark request as in progress
	cm.markRequestInProgress(routeHost.Hosts, true)
	defer cm.markRequestInProgress(routeHost.Hosts, false)

	logger.Debug("Requesting new certificate", "route", routeHost.Name, "domains", routeHost.Hosts)
	request := certificate.ObtainRequest{
		Domains: routeHost.Hosts,
		Bundle:  true,
	}

	certificates, err := cm.legoClient.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	certInfo := cm.createCertificateInfoFromACME(&cert, routeHost.Hosts, certificates)
	cm.storeCertificateInfo(routeHost.Hosts, certInfo)

	if err = cm.saveToStorage(); err != nil {
		logger.Error("Failed to save certificate to storage", "error", err)
	}

	logger.Info("Successfully obtained new certificate", "route", routeHost.Name, "domains", routeHost.Hosts)
	return &cert, nil
}
func (cm *CertManager) isRequestInProgress(domains []string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	key := cm.getRequestKey(domains)
	return cm.inProgressRequests[key]
}

func (cm *CertManager) markRequestInProgress(domains []string, inProgress bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.inProgressRequests == nil {
		cm.inProgressRequests = make(map[string]bool)
	}

	key := cm.getRequestKey(domains)
	cm.inProgressRequests[key] = inProgress
}

func (cm *CertManager) getRequestKey(domains []string) string {
	sort.Strings(domains)
	return strings.Join(domains, ",")
}

func (cm *CertManager) createCertificateInfoFromACME(cert *tls.Certificate, domains []string, resource *certificate.Resource) *CertificateInfo {
	parsedCert, _ := x509.ParseCertificate(cert.Certificate[0])
	return &CertificateInfo{
		Certificate: cert,
		Domains:     domains,
		Expires:     parsedCert.NotAfter,
		Resource:    resource,
	}
}

func (cm *CertManager) storeCertificateInfo(domains []string, certInfo *CertificateInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for domain := range cm.certs {
		if containsAny(domains, cm.certs[domain].Domains) {
			delete(cm.certs, domain)
		}
	}

	for _, domain := range domains {
		cm.certs[domain] = certInfo
	}
}

// Renewal service
func (cm *CertManager) startRenewalService() {
	if cm.renewalTicker != nil {
		cm.renewalTicker.Stop()
	}

	cm.renewalTicker = time.NewTicker(24 * time.Hour)
	go func() {
		for range cm.renewalTicker.C {
			cm.renewCertificates()
		}
	}()
}

func (cm *CertManager) renewCertificates() {
	certsToRenew := cm.getCertificatesToRenew()

	for _, domain := range certsToRenew {
		logger.Debug("Renewing certificate", "domain", domain)
		if _, err := cm.renewCertificate(domain); err != nil {
			logger.Error("Failed to renew certificate", "domain", domain, "error", err)
		}
	}
}

func (cm *CertManager) getCertificatesToRenew() []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var certsToRenew []string
	for domain, certInfo := range cm.certs {
		if certInfo.Resource != nil && time.Until(certInfo.Expires) < 30*24*time.Hour {
			certsToRenew = append(certsToRenew, domain)
		}
	}
	return certsToRenew
}

func (cm *CertManager) renewCertificate(domain string) (*tls.Certificate, error) {
	certInfo := cm.getCertificateInfo(domain)
	if certInfo == nil || certInfo.Resource == nil {
		return cm.obtainNewCertificateForDomain(domain)
	}

	return cm.renewExistingCertificate(certInfo)
}

func (cm *CertManager) getCertificateInfo(domain string) *CertificateInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.certs[domain]
}

func (cm *CertManager) obtainNewCertificateForDomain(domain string) (*tls.Certificate, error) {
	allowed, routeHost := cm.isHostAllowed(domain)
	if !allowed {
		return nil, fmt.Errorf("domain %q is not in the allowed hosts list", domain)
	}
	return cm.obtainCertificate(routeHost)
}

func (cm *CertManager) renewExistingCertificate(certInfo *CertificateInfo) (*tls.Certificate, error) {
	renewed, err := cm.legoClient.Certificate.Renew(*certInfo.Resource, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(renewed.Certificate, renewed.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create renewed TLS certificate: %w", err)
	}

	newCertInfo := cm.createCertificateInfoFromRenewal(&cert, certInfo.Domains, renewed)
	cm.updateCertificateInfo(certInfo.Domains, newCertInfo)

	logger.Debug("Certificate renewed", "domains", certInfo.Domains)
	return &cert, nil
}

func (cm *CertManager) createCertificateInfoFromRenewal(cert *tls.Certificate, domains []string, resource *certificate.Resource) *CertificateInfo {
	parsedCert, _ := x509.ParseCertificate(cert.Certificate[0])
	return &CertificateInfo{
		Certificate: cert,
		Domains:     domains,
		Expires:     parsedCert.NotAfter,
		Resource:    resource,
	}
}

func (cm *CertManager) updateCertificateInfo(domains []string, certInfo *CertificateInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, d := range domains {
		cm.certs[d] = certInfo
	}

	if err := cm.saveToStorage(); err != nil {
		logger.Error("Failed to save renewed certificate to storage", "error", err)
	}
}

func (cm *CertManager) findCertificateInfo(domain string) *CertificateInfo {
	if certInfo, exists := cm.certs[domain]; exists {
		return certInfo
	}
	// Fall back custom certs
	if certInfo, exists := cm.customCerts[domain]; exists {
		return certInfo
	}
	for _, d := range []string{getWildcardDomain(domain), getParentDomain(domain)} {
		if certInfo, exists := cm.certs[d]; exists {
			return certInfo
		}
	}
	for _, d := range []string{getWildcardDomain(domain), getParentDomain(domain)} {
		if certInfo, exists := cm.customCerts[d]; exists {
			return certInfo
		}
	}
	return nil
}

// Self-signed certificate generation
func (cm *CertManager) GenerateCertificate(domain string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
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
		logger.Error("Failed to generate self-signed certificate",
			"domain", domain,
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	cm.AddCertificate(domain, tlsCert)
	logger.Debug("Self-signed certificate generated", "domain", domain)
	return &tlsCert, nil
}

func (cm *CertManager) GenerateDefaultCertificate() (*tls.Certificate, error) {
	return cm.GenerateCertificate("GOMA DEFAULT CERT")
}

// Cleanup
func (cm *CertManager) Close() {
	if cm.renewalTicker != nil {
		cm.renewalTicker.Stop()
	}

	if err := cm.saveToStorage(); err != nil {
		logger.Error("Failed to save final state to storage", "error", err)
	}
}

// Helper functions
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
		return "", nil, fmt.Errorf("no certificate data found")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate: %v", err)
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
