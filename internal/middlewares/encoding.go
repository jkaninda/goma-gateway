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
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Content codings understood by the gateway.
const (
	EncodingIdentity = "identity"
	EncodingGzip     = "gzip"
	EncodingZstd     = "zstd"
	EncodingBrotli   = "br"
	EncodingDeflate  = "deflate"
)

// knownCodings are the codings the cache distinguishes in its keys, sorted.
var knownCodings = []string{EncodingBrotli, EncodingDeflate, EncodingGzip, EncodingZstd}

// coding is one coding's entry in an Accept-Encoding header.
type coding struct {
	q   float64
	set bool
}

// acceptEncoding is a parsed Accept-Encoding header. Only the codings the
// gateway reasons about get a slot, which keeps parsing allocation-free on a
// path every proxied request takes.
type acceptEncoding struct {
	present                                 bool // the header was sent at all
	gzip, br, zstd, deflate, identity, star coding
}

func (ae *acceptEncoding) slot(name string) *coding {
	switch {
	case strings.EqualFold(name, EncodingGzip), strings.EqualFold(name, "x-gzip"): // RFC 9110 §8.4.1.3
		return &ae.gzip
	case strings.EqualFold(name, EncodingBrotli):
		return &ae.br
	case strings.EqualFold(name, EncodingZstd):
		return &ae.zstd
	case strings.EqualFold(name, EncodingDeflate):
		return &ae.deflate
	case strings.EqualFold(name, EncodingIdentity):
		return &ae.identity
	case name == "*":
		return &ae.star
	}
	return nil
}

// parseAcceptEncoding parses Accept-Encoding per RFC 9110 §12.5.3. An entry
// with an unparseable q-value is dropped rather than read as q=1: a malformed
// header must never widen what the client said it accepts.
func parseAcceptEncoding(h http.Header) acceptEncoding {
	values := h.Values("Accept-Encoding")
	ae := acceptEncoding{present: len(values) > 0}
	for _, value := range values {
		for rest := value; rest != ""; {
			var part string
			part, rest, _ = strings.Cut(rest, ",")
			name, params, _ := strings.Cut(part, ";")
			c := ae.slot(strings.TrimSpace(name))
			if c == nil {
				continue
			}
			q, ok := parseQValue(params)
			if !ok {
				continue
			}
			// The highest q wins when a coding is repeated.
			if !c.set || q > c.q {
				c.q, c.set = q, true
			}
		}
	}
	return ae
}

// parseQValue reads the q parameter from an Accept-Encoding entry's
// parameters. No q parameter means q=1.
func parseQValue(params string) (float64, bool) {
	for rest := params; rest != ""; {
		var p string
		p, rest, _ = strings.Cut(rest, ";")
		k, v, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		q, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || q < 0 || q > 1 {
			return 0, false
		}
		return q, true
	}
	return 1, true
}

// weight is the q-value the client gives a coding.
func (ae *acceptEncoding) weight(name string) float64 {
	if c := ae.slot(name); c != nil && c.set {
		return c.q
	}
	if ae.star.set {
		return ae.star.q
	}
	return 0
}

// NegotiateEncoding picks the content coding for a response from the codings
// the gateway is willing to produce, listed in preference order. The coding
// with the highest q-value the client gives wins; a tie goes to the earlier
// entry in preference. It returns EncodingIdentity when the client sent no
// Accept-Encoding or accepts none of them.
func NegotiateEncoding(r *http.Request, preference []string) string {
	ae := parseAcceptEncoding(r.Header)
	if !ae.present {
		return EncodingIdentity
	}
	best, bestQ := EncodingIdentity, 0.0
	for _, coding := range preference {
		if q := ae.weight(coding); q > bestQ {
			best, bestQ = coding, q
		}
	}
	return best
}

// AcceptedCodingsKey reduces Accept-Encoding to the set of known codings the
// client accepts, sorted and joined ("br+gzip+zstd"), or "identity".
//
// The cache keys on this rather than on a single negotiated coding because the
// stored body's coding may be the upstream's choice, which the gateway cannot
// predict: two clients that accept different sets must never share an entry,
// or one is replayed a coding it cannot decode. Header permutations and
// q-values above zero still collapse to one key.
func AcceptedCodingsKey(r *http.Request) string {
	ae := parseAcceptEncoding(r.Header)
	if !ae.present {
		return EncodingIdentity
	}
	var b strings.Builder
	for _, coding := range knownCodings {
		if ae.weight(coding) > 0 {
			if b.Len() > 0 {
				b.WriteByte('+')
			}
			b.WriteString(coding)
		}
	}
	if b.Len() == 0 {
		return EncodingIdentity
	}
	return b.String()
}

// AcceptsEncoding reports whether the client accepts coding. Identity is
// accepted unless explicitly refused (identity;q=0, or *;q=0 without it).
func AcceptsEncoding(r *http.Request, coding string) bool {
	ae := parseAcceptEncoding(r.Header)
	if coding == EncodingIdentity || coding == "" {
		if ae.identity.set {
			return ae.identity.q > 0
		}
		return !ae.star.set || ae.star.q > 0
	}
	return ae.weight(coding) > 0
}

// IsSupportedEncoding reports whether the gateway can produce coding.
func IsSupportedEncoding(coding string) bool {
	return slices.Contains([]string{EncodingGzip, EncodingZstd, EncodingBrotli}, coding)
}
