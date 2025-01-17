package internal

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
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
	middlewareList := []string{BasicAuth, JWTAuth, AccessMiddleware, accessPolicy, addPrefix, rateLimit, strings.ToLower(rateLimit), redirectRegex, forwardAuth, rewriteRegex, httpCache}
	return slices.Contains(middlewareList, tyName)
}
func GetMiddleware(rule string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if strings.Contains(rule, m.Name) {

			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("no middlewares found with name " + rule)
}

// loadExtraMiddlewares loads additional middlewares
func loadExtraMiddlewares(routePath string) ([]Middleware, error) {
	yamlFiles, err := loadExtraFiles(routePath)
	if err != nil {
		return nil, fmt.Errorf("error loading extra files: %v", err)
	}
	var extraMiddlewares []Middleware
	for _, yamlFile := range yamlFiles {
		buf, err := os.ReadFile(yamlFile)
		if err != nil {
			return nil, fmt.Errorf("error loading extra file: %v", err)
		}
		ex := &ExtraMiddleware{}
		err = yaml.Unmarshal(buf, ex)
		if err != nil {
			return nil, fmt.Errorf("in file %q: %w", ConfigFile, err)
		}
		extraMiddlewares = append(extraMiddlewares, ex.Middlewares...)

	}
	if len(extraMiddlewares) == 0 {
		return nil, fmt.Errorf("no extra middleware found")
	}
	return extraMiddlewares, nil
}

// findDuplicateMiddlewareNames finds duplicated middleware name
func findDuplicateMiddlewareNames(middlewares []Middleware) []string {
	// Create a map to track occurrences of names
	nameMap := make(map[string]int)
	var duplicates []string

	for _, mid := range middlewares {
		nameMap[mid.Name]++
		// If the count is ==2, it's a duplicate
		if nameMap[mid.Name] == 2 {
			duplicates = append(duplicates, mid.Name)
		}
	}
	return duplicates
}
