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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Session store kinds.
const (
	SessionStoreCookie = "cookie"
	SessionStoreMemory = "memory"
	SessionStoreRedis  = "redis"
)

const (
	// DefaultSessionTTL bounds how long a session lives regardless of activity.
	DefaultSessionTTL = 12 * time.Hour
	// DefaultSessionCookieName is the cookie holding the session.
	DefaultSessionCookieName = "goma_session"

	// maxCookieChunkBytes keeps each cookie under the 4KB browsers accept, with
	// room for the name and attributes.
	maxCookieChunkBytes = 3500
	// maxCookieChunks bounds how far a chunked session may be split, so a
	// malformed request cannot make the gateway walk an unbounded cookie list.
	maxCookieChunks = 8
	// sessionTouchInterval is how often an active session's last-seen timestamp
	// is written back. Writing on every request would mean a Set-Cookie, or a
	// Redis round trip, per request.
	sessionTouchInterval = time.Minute

	redisSessionPrefix = "goma:oidc:session:"
	sessionIDBytes     = 32
)

var errNoSession = errors.New("no session")

// Session is what the gateway remembers about a signed-in user. It never
// reaches the browser in readable form: cookie-backed sessions are sealed, and
// server-backed sessions leave only an opaque identifier behind.
type Session struct {
	AccessToken  string                 `json:"at,omitempty"`
	RefreshToken string                 `json:"rt,omitempty"`
	IDToken      string                 `json:"it,omitempty"`
	Claims       map[string]interface{} `json:"cl,omitempty"`
	IssuedAt     int64                  `json:"iat"`
	LastSeen     int64                  `json:"ls"`
}

func (s *Session) expired(ttl, idleTimeout time.Duration) bool {
	now := time.Now().Unix()
	if ttl > 0 && now-s.IssuedAt > int64(ttl.Seconds()) {
		return true
	}
	if idleTimeout > 0 && now-s.LastSeen > int64(idleTimeout.Seconds()) {
		return true
	}
	return false
}

// needsTouch reports whether the last-seen timestamp is stale enough to be
// worth writing back.
func (s *Session) needsTouch() bool {
	return time.Now().Unix()-s.LastSeen > int64(sessionTouchInterval.Seconds())
}

// SessionStore persists a signed-in user's session between requests.
type SessionStore interface {
	Load(r *http.Request) (*Session, error)
	Save(w http.ResponseWriter, r *http.Request, session *Session) error
	Clear(w http.ResponseWriter, r *http.Request)
}

// SessionOptions configures a store and the cookie that addresses it.
type SessionOptions struct {
	Store       string
	Secret      string
	TTL         time.Duration
	IdleTimeout time.Duration

	CookieName   string
	CookiePath   string
	CookieDomain string
	CookieSecure *bool
	SameSite     http.SameSite
}

func (o SessionOptions) cookieName() string {
	if o.CookieName == "" {
		return DefaultSessionCookieName
	}
	return o.CookieName
}

func (o SessionOptions) ttl() time.Duration {
	if o.TTL <= 0 {
		return DefaultSessionTTL
	}
	return o.TTL
}

// NewSessionStore builds the store named by opts. The secret keys the sealing
// of session data; callers derive one from the client secret when the operator
// has not configured one.
func NewSessionStore(opts SessionOptions) (SessionStore, error) {
	sealer, err := newSealer(opts.Secret, "goma-oidc-session")
	if err != nil {
		return nil, err
	}

	switch opts.Store {
	case "", SessionStoreCookie:
		return &cookieSessionStore{opts: opts, sealer: sealer}, nil
	case SessionStoreMemory:
		return &memorySessionStore{opts: opts, sessions: make(map[string]*Session)}, nil
	case SessionStoreRedis:
		if RedisClient == nil {
			return nil, fmt.Errorf("session store %q requires redis to be configured on the gateway", SessionStoreRedis)
		}
		return &redisSessionStore{opts: opts, sealer: sealer}, nil
	default:
		return nil, fmt.Errorf("unknown session store %q, expected cookie, memory or redis", opts.Store)
	}
}

// cookieSessionStore keeps the whole session in the browser, sealed. It needs
// no shared state, so it works across replicas without a database — at the cost
// of a large cookie on every request.
type cookieSessionStore struct {
	opts   SessionOptions
	sealer *sealer
}

func (c *cookieSessionStore) Load(r *http.Request) (*Session, error) {
	sealed := readChunkedCookie(r, c.opts.cookieName())
	if sealed == "" {
		return nil, errNoSession
	}
	plaintext, err := c.sealer.open(sealed)
	if err != nil {
		return nil, fmt.Errorf("session cookie could not be opened: %w", err)
	}
	session := &Session{}
	if err := json.Unmarshal(plaintext, session); err != nil {
		return nil, fmt.Errorf("session cookie is malformed: %w", err)
	}
	if session.expired(c.opts.ttl(), c.opts.IdleTimeout) {
		return nil, errNoSession
	}
	return session, nil
}

func (c *cookieSessionStore) Save(w http.ResponseWriter, r *http.Request, session *Session) error {
	plaintext, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return writeChunkedCookie(w, r, c.opts, c.sealer.seal(plaintext))
}

func (c *cookieSessionStore) Clear(w http.ResponseWriter, r *http.Request) {
	clearChunkedCookie(w, r, c.opts)
}

// memorySessionStore keeps sessions in this process. Sessions do not survive a
// restart and are not shared between replicas.
type memorySessionStore struct {
	opts     SessionOptions
	mu       sync.Mutex
	sessions map[string]*Session
}

func (m *memorySessionStore) Load(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(m.opts.cookieName())
	if err != nil || cookie.Value == "" {
		return nil, errNoSession
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[cookie.Value]
	if !ok {
		return nil, errNoSession
	}
	if session.expired(m.opts.ttl(), m.opts.IdleTimeout) {
		delete(m.sessions, cookie.Value)
		return nil, errNoSession
	}
	copied := *session
	return &copied, nil
}

func (m *memorySessionStore) Save(w http.ResponseWriter, r *http.Request, session *Session) error {
	id, err := sessionIDFrom(r, m.opts.cookieName())
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.pruneLocked()
	m.sessions[id] = session
	m.mu.Unlock()

	http.SetCookie(w, newSessionCookie(r, m.opts, id, 0))
	return nil
}

func (m *memorySessionStore) Clear(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(m.opts.cookieName()); err == nil {
		m.mu.Lock()
		delete(m.sessions, cookie.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, newSessionCookie(r, m.opts, "", -1))
}

func (m *memorySessionStore) pruneLocked() {
	for id, session := range m.sessions {
		if session.expired(m.opts.ttl(), m.opts.IdleTimeout) {
			delete(m.sessions, id)
		}
	}
}

// redisSessionStore keeps sessions in Redis, shared across replicas and
// surviving a restart. Payloads are sealed, so a Redis dump does not hand over
// everyone's tokens.
type redisSessionStore struct {
	opts   SessionOptions
	sealer *sealer
}

func (s *redisSessionStore) Load(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(s.opts.cookieName())
	if err != nil || cookie.Value == "" {
		return nil, errNoSession
	}

	sealed, err := RedisClient.Get(r.Context(), redisSessionPrefix+cookie.Value).Result()
	if err != nil || sealed == "" {
		return nil, errNoSession
	}
	plaintext, err := s.sealer.open(sealed)
	if err != nil {
		return nil, fmt.Errorf("stored session could not be opened: %w", err)
	}
	session := &Session{}
	if err := json.Unmarshal(plaintext, session); err != nil {
		return nil, fmt.Errorf("stored session is malformed: %w", err)
	}
	if session.expired(s.opts.ttl(), s.opts.IdleTimeout) {
		return nil, errNoSession
	}
	return session, nil
}

func (s *redisSessionStore) Save(w http.ResponseWriter, r *http.Request, session *Session) error {
	id, err := sessionIDFrom(r, s.opts.cookieName())
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(session)
	if err != nil {
		return err
	}
	if err := RedisClient.Set(r.Context(), redisSessionPrefix+id,
		s.sealer.seal(plaintext), s.opts.ttl()).Err(); err != nil {
		return fmt.Errorf("failed to store the session: %w", err)
	}
	http.SetCookie(w, newSessionCookie(r, s.opts, id, 0))
	return nil
}

func (s *redisSessionStore) Clear(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(s.opts.cookieName()); err == nil && cookie.Value != "" {
		if err := RedisClient.Del(context.WithoutCancel(r.Context()),
			redisSessionPrefix+cookie.Value).Err(); err != nil {
			logger.Warn("Failed to delete the stored session", "error", err)
		}
	}
	http.SetCookie(w, newSessionCookie(r, s.opts, "", -1))
}

// sessionIDFrom reuses the identifier the browser already holds, so refreshing
// a session does not orphan the previous entry, and mints a new one otherwise.
func sessionIDFrom(r *http.Request, cookieName string) (string, error) {
	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		return cookie.Value, nil
	}
	return randomToken(sessionIDBytes)
}

func newSessionCookie(r *http.Request, opts SessionOptions, value string, maxAge int) *http.Cookie {
	path := opts.CookiePath
	if path == "" {
		path = "/"
	}
	secure := scheme(r) == schemeHTTPS
	if opts.CookieSecure != nil {
		secure = *opts.CookieSecure
	}
	sameSite := opts.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	cookie := &http.Cookie{
		Name:     opts.cookieName(),
		Value:    value,
		Path:     path,
		Domain:   opts.CookieDomain,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	}
	if maxAge != 0 {
		cookie.MaxAge = maxAge
	}
	return cookie
}

// readChunkedCookie reassembles a value split across "<name>", "<name>-1", …
func readChunkedCookie(r *http.Request, name string) string {
	first, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	value := first.Value
	for index := 1; index < maxCookieChunks; index++ {
		chunk, err := r.Cookie(name + "-" + strconv.Itoa(index))
		if err != nil {
			break
		}
		value += chunk.Value
	}
	return value
}

func writeChunkedCookie(w http.ResponseWriter, r *http.Request, opts SessionOptions, value string) error {
	chunks := splitChunks(value, maxCookieChunkBytes)
	// Writing more chunks than a read can reassemble would leave the browser
	// holding a session that never opens again.
	if len(chunks) > maxCookieChunks {
		return fmt.Errorf("session is %d bytes, too large for cookie storage (%d bytes): "+
			"forward fewer claims or use session.store redis", len(value), maxCookieChunks*maxCookieChunkBytes)
	}
	for index, chunk := range chunks {
		cookie := newSessionCookie(r, opts, chunk, 0)
		if index > 0 {
			cookie.Name = opts.cookieName() + "-" + strconv.Itoa(index)
		}
		http.SetCookie(w, cookie)
	}
	// A session that shrank must not leave stale trailing chunks behind: they
	// would be concatenated onto the next read and fail to open.
	for index := len(chunks); index < maxCookieChunks; index++ {
		if _, err := r.Cookie(opts.cookieName() + "-" + strconv.Itoa(index)); err != nil {
			break
		}
		expired := newSessionCookie(r, opts, "", -1)
		expired.Name = opts.cookieName() + "-" + strconv.Itoa(index)
		http.SetCookie(w, expired)
	}
	return nil
}

func clearChunkedCookie(w http.ResponseWriter, r *http.Request, opts SessionOptions) {
	http.SetCookie(w, newSessionCookie(r, opts, "", -1))
	for index := 1; index < maxCookieChunks; index++ {
		name := opts.cookieName() + "-" + strconv.Itoa(index)
		if _, err := r.Cookie(name); err != nil {
			break
		}
		expired := newSessionCookie(r, opts, "", -1)
		expired.Name = name
		http.SetCookie(w, expired)
	}
}

func splitChunks(value string, size int) []string {
	if len(value) <= size {
		return []string{value}
	}
	chunks := make([]string, 0, len(value)/size+1)
	for len(value) > size {
		chunks = append(chunks, value[:size])
		value = value[size:]
	}
	return append(chunks, value)
}

// sealer encrypts session and flow data with AES-GCM under a key derived from
// the configured secret.
type sealer struct {
	aead cipher.AEAD
}

func newSealer(secret, info string) (*sealer, error) {
	if secret == "" {
		return nil, errors.New("empty secret")
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, []byte(info)), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

func (s *sealer) seal(plaintext []byte) string {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		// crypto/rand does not fail on any supported platform; a failure here
		// means the process cannot produce safe output at all.
		panic("goma: crypto/rand is unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plaintext, nil))
}

func (s *sealer) open(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(raw) < s.aead.NonceSize() {
		return nil, errors.New("value is too short")
	}
	nonce, ciphertext := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	return s.aead.Open(nil, nonce, ciphertext, nil)
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
