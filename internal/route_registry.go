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
	"errors"
	"net/http"
	"strings"

	"github.com/jkaninda/njia"
)

// proxyCatchAllParam names the parameter that absorbs everything below a
// route's path. Every prefix registration uses the same name, so two routes at
// different depths never disagree about what a position is called.
const proxyCatchAllParam = "gomaPath"

// selfPattern and subPattern are the two templates that together cover a
// group's own path and everything beneath it.
const (
	selfPattern = "/"
	subPattern  = "/{" + proxyCatchAllParam + "...}"
)

// newProxyRouter returns a router configured the way the gateway expects.
//
// StrictSlash maps onto RedirectTrailingSlash: gorilla redirected a request
// whose path differed from a route's template only by a trailing slash, and
// njia does the same when only one of the two forms is registered.
func newProxyRouter(strictSlash bool) *njia.Router {
	rt := njia.New()
	rt.RedirectTrailingSlash = strictSlash
	// Defence in depth behind canonicalizePath: if a request ever reaches the
	// router un-normalised, redirect it rather than routing the raw form.
	rt.CleanPath = true
	return rt
}

// groupPrefix normalises a configured route path into the prefix its njia group
// is rooted at. The empty string is the root, which njia joins away.
func groupPrefix(path string) string {
	p := strings.TrimRight(path, "/")
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// registerPrefix registers h on the group for its own path and everything
// beneath it.
//
// A duplicate is reported rather than returned: two routes sharing a path used
// to be resolved by gorilla in favour of whichever was registered first, and
// configurations relying on that should not start failing to load.
func registerPrefix(g *njia.Group, method, name string, h http.Handler, opts ...njia.RouteOption) error {
	for _, pattern := range [...]string{selfPattern, subPattern} {
		err := g.Handle(method, pattern, h, opts...)
		switch {
		case err == nil:
		case errors.Is(err, njia.ErrDuplicateRoute):
			logger.Warn("Route path already registered, keeping the first one",
				"route", name, "path", g.Prefix()+pattern)
		default:
			return err
		}
	}
	return nil
}
