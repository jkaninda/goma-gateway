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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	goutils "github.com/jkaninda/go-utils"
)

// vaultPKIClient is a minimal HashiCorp Vault PKI client. It issues leaf
// certificates through the PKI secrets engine and returns a PEM bundle ready
// for tls.X509KeyPair.
type vaultPKIClient struct {
	address    string
	token      string
	mount      string
	role       string
	ttl        string
	namespace  string
	httpClient *http.Client
}

// issuedCertificate holds a certificate freshly issued by Vault.
type issuedCertificate struct {
	// CertPEM is the leaf certificate followed by the issuing CA chain.
	CertPEM []byte
	// KeyPEM is the private key.
	KeyPEM []byte
}

// vaultIssueResponse mirrors the relevant fields of the Vault PKI issue reply.
type vaultIssueResponse struct {
	Data struct {
		Certificate string   `json:"certificate"`
		IssuingCA   string   `json:"issuing_ca"`
		CAChain     []string `json:"ca_chain"`
		PrivateKey  string   `json:"private_key"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// newVaultPKIClient builds a client from the provider's Vault config. The
// address and token fall back to the standard VAULT_ADDR / VAULT_TOKEN
// environment variables (which take precedence over the config file), and the
// namespace to VAULT_NAMESPACE.
func newVaultPKIClient(cfg Vault) (*vaultPKIClient, error) {
	address := strings.TrimRight(goutils.Env("VAULT_ADDR", cfg.Address), "/")
	token := goutils.Env("VAULT_TOKEN", cfg.Token)
	namespace := goutils.Env("VAULT_NAMESPACE", cfg.Namespace)

	if address == "" {
		return nil, errors.New("vault address is required (set vault.address or VAULT_ADDR)")
	}
	if token == "" {
		return nil, errors.New("vault token is required (set vault.token or VAULT_TOKEN)")
	}
	if cfg.Role == "" {
		return nil, errors.New("vault role is required")
	}

	mount := cfg.Mount
	if mount == "" {
		mount = defaultVaultMount
	}

	transport := &http.Transport{}
	// Mirror the ACME client's behavior: skip TLS verification only in local /
	// development environments so a self-signed Vault dev server can be used.
	if env := os.Getenv(gomaEnv); env == development || env == local {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &vaultPKIClient{
		address:    address,
		token:      token,
		mount:      strings.Trim(mount, "/"),
		role:       cfg.Role,
		ttl:        cfg.Ttl,
		namespace:  namespace,
		httpClient: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// IssueCertificate requests a certificate for the given hosts. The first host is
// used as the common name; the remainder become subject alternative names.
func (c *vaultPKIClient) IssueCertificate(hosts []string) (*issuedCertificate, error) {
	if len(hosts) == 0 {
		return nil, errors.New("no hosts provided for vault certificate request")
	}

	payload := map[string]string{
		"common_name": hosts[0],
		"format":      "pem",
	}
	if len(hosts) > 1 {
		payload["alt_names"] = strings.Join(hosts[1:], ",")
	}
	if c.ttl != "" {
		payload["ttl"] = c.ttl
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vault request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/issue/%s", c.address, c.mount, c.role)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault response: %w", err)
	}

	var parsed vaultIssueResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse vault response (status %d): %w", resp.StatusCode, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(parsed.Errors) > 0 {
			return nil, fmt.Errorf("vault returned status %d: %s", resp.StatusCode, strings.Join(parsed.Errors, "; "))
		}
		return nil, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	if parsed.Data.Certificate == "" || parsed.Data.PrivateKey == "" {
		return nil, errors.New("vault response missing certificate or private key")
	}

	return &issuedCertificate{
		CertPEM: buildCertChain(parsed.Data.Certificate, parsed.Data.CAChain, parsed.Data.IssuingCA),
		KeyPEM:  []byte(ensureTrailingNewline(parsed.Data.PrivateKey)),
	}, nil
}

// buildCertChain concatenates the leaf certificate with its issuing CA chain so
// the served bundle includes the necessary intermediates. It prefers the full
// ca_chain and falls back to the single issuing_ca.
func buildCertChain(leaf string, caChain []string, issuingCA string) []byte {
	var buf bytes.Buffer
	buf.WriteString(ensureTrailingNewline(leaf))

	if len(caChain) > 0 {
		for _, ca := range caChain {
			if strings.TrimSpace(ca) != "" {
				buf.WriteString(ensureTrailingNewline(ca))
			}
		}
	} else if strings.TrimSpace(issuingCA) != "" {
		buf.WriteString(ensureTrailingNewline(issuingCA))
	}

	return buf.Bytes()
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}
