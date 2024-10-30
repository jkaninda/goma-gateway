package pkg

import (
	"errors"
	"github.com/gorilla/mux"
	"slices"
	"strings"
)

func getMiddleware(rules []string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if slices.Contains(rules, m.Name) {
			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("middleware not found with name:  [" + strings.Join(rules, ";") + "]")
}

type RoutePath struct {
	route       Route
	path        string
	rules       []string
	middlewares []Middleware
	router      *mux.Router
}

func doesExist(tyName string) bool {
	middlewareList := []string{BasicAuth, JWTAuth, AccessMiddleware}
	if slices.Contains(middlewareList, tyName) {
		return true

	}
	return false
}
