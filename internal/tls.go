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
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
)

func (gatewayServer GatewayServer) initTLS() (*tls.Config, bool, error) {
	tlsConfig := loadTLS()
	cert, err := loadGatewayCertificate(gatewayServer)
	if err == nil {
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	if tlsConfig != nil {
		return tlsConfig, true, nil
	}
	return nil, false, fmt.Errorf("failed to load TLS config")

}

// loadTLS loads TLS Certificate
func loadCert(cert, key string) (tls.Certificate, error) {
	if cert == "" && key == "" {
		return tls.Certificate{}, fmt.Errorf("no certificate or key file provided")
	}
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return serverCert, nil
}

func loadTLS() *tls.Config {
	cfg := &tls.Config{}
	for _, route := range dynamicRoutes {
		if len(route.TLS.Keys) > 0 {
			for _, key := range route.TLS.Keys {
				if key.Key == "" && key.Cert == "" {
					logger.Error("Error tls: no certificate or key file provided for route: %s", route.Name)
					continue
				}
				certificate, err := loadCert(key.Cert, key.Key)
				if err != nil {
					logger.Error("Error loading server certificate: %v", err)
					continue
				}
				cfg.Certificates = append(cfg.Certificates, certificate)
			}
		}

	}
	return cfg
}
func loadGatewayCertificate(gatewayServer GatewayServer) (tls.Certificate, error) {
	loadAndWarn := func(cert, key string, warnMsg string) (tls.Certificate, error) {
		if len(cert) != 0 || len(key) != 0 {
			if warnMsg != "" {
				logger.Warn("sslCertFile and sslKeyFile are deprecated, please use tlsCertFile and tlsKeyFile instead")
			}
			certificate, err := loadCert(cert, key)
			if err != nil {
				logger.Error("Error loading server certificate: %v", err)
			}
			return certificate, nil
		}
		return tls.Certificate{}, nil
	}
	// Check deprecated fields
	certificate, err := loadAndWarn(
		gatewayServer.gateway.SSLCertFile,
		gatewayServer.gateway.SSLKeyFile,
		"Warn",
	)
	if err != nil {
		return certificate, err
	}

	// Check new fields
	return loadAndWarn(
		gatewayServer.gateway.TlsCertFile,
		gatewayServer.gateway.TlsKeyFile,
		"",
	)
}
