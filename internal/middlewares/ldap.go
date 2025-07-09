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

package middlewares

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"strings"
)

type LDAP struct {
	URL                string
	BaseDN             string
	BindDN             string
	BindPass           string
	UserFilter         string
	StartTLS           bool
	InsecureSkipVerify bool
}

// authenticateLDAP performs LDAP authentication.
func (l *LDAP) authenticateLDAP(username, password string) bool {
	conn, err := l.connect()
	if err != nil {
		logger.Error("Failed to connect to LDAP server", "error", err)
		return false
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			logger.Error("Failed to close LDAP connection", "error", cerr)
		}
	}()

	if err = l.bindServiceAccount(conn); err != nil {
		logger.Error("Service account bind failed", "error", err)
		return false
	}

	userDN, err := l.searchUserDN(conn, username)
	if err != nil {
		logger.Warn("User search failed", "user", username, "error", err)
		return false
	}

	if err = conn.Bind(userDN, password); err != nil {
		logger.Warn("User authentication failed", "user", username, "error", err)
		return false
	}

	return true
}

func (l *LDAP) connect() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(l.URL, ldap.DialWithTLSConfig(&tls.Config{
		InsecureSkipVerify: l.InsecureSkipVerify,
	}))
	if err != nil {
		return nil, err
	}

	if !strings.HasPrefix(l.URL, "ldaps://") && l.StartTLS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: l.InsecureSkipVerify})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	return conn, nil
}

func (l *LDAP) bindServiceAccount(conn *ldap.Conn) error {
	if l.BindDN == "" || l.BindPass == "" {
		return nil
	}
	return conn.Bind(l.BindDN, l.BindPass)
}

func (l *LDAP) searchUserDN(conn *ldap.Conn, username string) (string, error) {
	safeUsername := ldap.EscapeFilter(username)
	filter := fmt.Sprintf(l.UserFilter, safeUsername)
	req := ldap.NewSearchRequest(
		l.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		nil,
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("LDAP search error: %w", err)
	}

	switch len(res.Entries) {
	case 0:
		return "", fmt.Errorf("user %q not found", username)
	case 1:
		return res.Entries[0].DN, nil
	default:
		return "", fmt.Errorf("multiple entries found for user %q", username)
	}
}
