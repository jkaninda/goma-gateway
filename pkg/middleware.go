package pkg

import (
	"errors"
	"github.com/gorilla/mux"
	"slices"
	"strings"
)

func searchMiddleware(rules []string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if slices.Contains(rules, m.Name) {
			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("no middleware found with name " + strings.Join(rules, ";"))
}
func getMiddleware(rule string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if strings.Contains(rule, m.Name) {

			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("no middleware found with name " + rule)
}

type RoutePath struct {
	route       Route
	path        string
	rules       []string
	middlewares []Middleware
	router      *mux.Router
}
