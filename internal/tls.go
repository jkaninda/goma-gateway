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

package pkg

import (
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
)

func (gatewayServer GatewayServer) initTLS() (*tls.Config, bool, error) {
	cert, key := gatewayServer.gateway.SSLCertFile, gatewayServer.gateway.SSLKeyFile
	if cert == "" || key == "" {
		return nil, false, nil
	}

	tlsConfig, err := loadTLS(cert, key)
	if err != nil {
		return nil, false, fmt.Errorf("failed to load TLS config: %w", err)
	}
	return tlsConfig, true, nil
}

// loadTLS loads TLS Certificate
func loadTLS(cert, key string) (*tls.Config, error) {
	if cert == "" && key == "" {
		return nil, fmt.Errorf("no certificate or key file provided")
	}
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		logger.Error("Error loading server certificate: %v", err)
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	return tlsConfig, nil
}
