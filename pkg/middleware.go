package pkg

import (
	"errors"
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

func doesExist(tyName string) bool {
	middlewareList := []string{BasicAuth, JWTAuth, AccessMiddleware}
	if slices.Contains(middlewareList, tyName) {
		return true

	}
	return false
}
func GetMiddleware(rule string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if strings.Contains(rule, m.Name) {

			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("no middleware found with name " + rule)
}
