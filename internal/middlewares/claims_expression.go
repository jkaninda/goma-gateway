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
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"regexp"
	"strings"
)

// Expression types for claims validation
type Expression interface {
	Evaluate(claims jwt.MapClaims) (bool, error)
}

// EqualsExpr checks if claim equals expected value
type EqualsExpr struct {
	ClaimKey string
	Expected string
}

func Equals(claimKey, expected string) *EqualsExpr {
	return &EqualsExpr{ClaimKey: claimKey, Expected: expected}
}

func (e *EqualsExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	value, err := extractClaimValue(claims, e.ClaimKey)
	if err != nil {
		return false, err
	}

	switch v := value.(type) {
	case string:
		return v == e.Expected, nil
	case []interface{}:
		// Check if any value in array matches
		for _, item := range v {
			if str, ok := item.(string); ok && str == e.Expected {
				return true, nil
			}
		}
		return false, nil
	default:
		return fmt.Sprintf("%v", v) == e.Expected, nil
	}
}

// PrefixExpr checks if claim starts with prefix
type PrefixExpr struct {
	ClaimKey string
	Prefix   string
}

func Prefix(claimKey, prefix string) *PrefixExpr {
	return &PrefixExpr{ClaimKey: claimKey, Prefix: prefix}
}

func (p *PrefixExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	value, err := extractClaimValue(claims, p.ClaimKey)
	if err != nil {
		return false, err
	}

	switch v := value.(type) {
	case string:
		return strings.HasPrefix(v, p.Prefix), nil
	case []interface{}:
		// Check if any value in array has the prefix
		for _, item := range v {
			if str, ok := item.(string); ok && strings.HasPrefix(str, p.Prefix) {
				return true, nil
			}
		}
		return false, nil
	default:
		str := fmt.Sprintf("%v", v)
		return strings.HasPrefix(str, p.Prefix), nil
	}
}

// ContainsExpr checks if claim contains substring or array contains value
type ContainsExpr struct {
	ClaimKey string
	Values   []string // Support for multiple values
	IsArray  bool     // Whether to check array membership vs substring
}

func Contains(claimKey string, values ...string) *ContainsExpr {
	return &ContainsExpr{
		ClaimKey: claimKey,
		Values:   values,
		IsArray:  len(values) > 1, // If multiple values, treat as array membership check
	}
}

func (c *ContainsExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	value, err := extractClaimValue(claims, c.ClaimKey)
	if err != nil {
		return false, err
	}

	switch v := value.(type) {
	case string:
		if c.IsArray {
			// Check if string value is one of the expected values
			for _, expected := range c.Values {
				if v == expected {
					return true, nil
				}
			}
			return false, nil
		} else {
			// Original substring behavior for single value
			return strings.Contains(v, c.Values[0]), nil
		}
	case []interface{}:
		if c.IsArray {
			// Check if array contains any of the expected values
			for _, item := range v {
				if str, ok := item.(string); ok {
					for _, expected := range c.Values {
						if str == expected {
							return true, nil
						}
					}
				}
			}
			return false, nil
		} else {
			// Check if any value in array contains the substring
			for _, item := range v {
				if str, ok := item.(string); ok && strings.Contains(str, c.Values[0]) {
					return true, nil
				}
			}
			return false, nil
		}
	default:
		str := fmt.Sprintf("%v", v)
		if c.IsArray {
			for _, expected := range c.Values {
				if str == expected {
					return true, nil
				}
			}
			return false, nil
		} else {
			return strings.Contains(str, c.Values[0]), nil
		}
	}
}

type OneOfExpr struct {
	ClaimKey string
	Values   []string
}

func OneOf(claimKey string, values ...string) *OneOfExpr {
	return &OneOfExpr{ClaimKey: claimKey, Values: values}
}

func (o *OneOfExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	value, err := extractClaimValue(claims, o.ClaimKey)
	if err != nil {
		return false, err
	}

	switch v := value.(type) {
	case string:
		for _, expected := range o.Values {
			if v == expected {
				return true, nil
			}
		}
		return false, nil
	case []interface{}:
		// Check if any value in the claim array matches any of the expected values
		for _, item := range v {
			if str, ok := item.(string); ok {
				for _, expected := range o.Values {
					if str == expected {
						return true, nil
					}
				}
			}
		}
		return false, nil
	default:
		str := fmt.Sprintf("%v", v)
		for _, expected := range o.Values {
			if str == expected {
				return true, nil
			}
		}
		return false, nil
	}
}

type AndExpr struct {
	Left  Expression
	Right Expression
}

func (a *AndExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	leftResult, err := a.Left.Evaluate(claims)
	if err != nil {
		return false, err
	}
	if !leftResult {
		return false, nil // Short-circuit evaluation
	}
	return a.Right.Evaluate(claims)
}

type OrExpr struct {
	Left  Expression
	Right Expression
}

func (o *OrExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	leftResult, err := o.Left.Evaluate(claims)
	if err != nil {
		return false, err
	}
	if leftResult {
		return true, nil // Short-circuit evaluation
	}
	return o.Right.Evaluate(claims)
}

type NotExpr struct {
	Expr Expression
}

func (n *NotExpr) Evaluate(claims jwt.MapClaims) (bool, error) {
	result, err := n.Expr.Evaluate(claims)
	if err != nil {
		return false, err
	}
	return !result, nil
}

func And(left, right Expression) *AndExpr {
	return &AndExpr{Left: left, Right: right}
}

func Or(left, right Expression) *OrExpr {
	return &OrExpr{Left: left, Right: right}
}

func Not(expr Expression) *NotExpr {
	return &NotExpr{Expr: expr}
}

type ExpressionParser struct {
	input  string
	pos    int
	length int
}

func ParseExpression(input string) (Expression, error) {
	parser := &ExpressionParser{
		input:  strings.TrimSpace(input),
		pos:    0,
		length: len(strings.TrimSpace(input)),
	}
	return parser.parseOrExpression()
}

func (p *ExpressionParser) parseOrExpression() (Expression, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for p.pos < p.length && p.peek() == "||" {
		err = p.consume("||")
		if err != nil {
			return nil, err
		}
		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}
		left = Or(left, right)
	}

	return left, nil
}

func (p *ExpressionParser) parseAndExpression() (Expression, error) {
	left, err := p.parseNotExpression()
	if err != nil {
		return nil, err
	}

	for p.pos < p.length && p.peek() == "&&" {
		err := p.consume("&&")
		if err != nil {
			return nil, err
		}
		right, err := p.parseNotExpression()
		if err != nil {
			return nil, err
		}
		left = And(left, right)
	}

	return left, nil
}

func (p *ExpressionParser) parseNotExpression() (Expression, error) {
	if p.peek() == "!" {
		err := p.consume("!")
		if err != nil {
			return nil, err
		}
		expr, err := p.parseNotExpression()
		if err != nil {
			return nil, err
		}
		return Not(expr), nil
	}

	return p.parseUnaryExpression()
}

func (p *ExpressionParser) parseUnaryExpression() (Expression, error) {
	if p.peek() == "(" {
		err := p.consume("(")
		if err != nil {
			return nil, err
		}
		expr, err := p.parseOrExpression()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("expected ')' at position %d", p.pos)
		}
		err = p.consume(")")
		if err != nil {
			return nil, err
		}
		return expr, nil
	}

	return p.parseFunction()
}

func (p *ExpressionParser) parseFunction() (Expression, error) {
	p.skipWhitespace()

	// Match function patterns - updated to support multiple parameters
	singleParamPattern := regexp.MustCompile(`^(Equals|Prefix)\s*\(\s*` + "`" + `([^` + "`" + `]+)` + "`" + `\s*,\s*` + "`" + `([^` + "`" + `]*)` + "`" + `\s*\)`)
	multiParamPattern := regexp.MustCompile(`^(Contains|OneOf)\s*\(\s*` + "`" + `([^` + "`" + `]+)` + "`" + `\s*,\s*(.+?)\s*\)`)

	if p.pos >= p.length {
		return nil, fmt.Errorf("unexpected end of input")
	}

	remaining := p.input[p.pos:]

	// Try single parameter functions first
	if match := singleParamPattern.FindStringSubmatch(remaining); match != nil {
		funcName := match[1]
		claimKey := match[2]
		value := match[3]

		p.pos += len(match[0])

		switch funcName {
		case "Equals":
			return Equals(claimKey, value), nil
		case "Prefix":
			return Prefix(claimKey, value), nil
		default:
			return nil, fmt.Errorf("unknown function: %s", funcName)
		}
	}

	// Try multi-parameter functions
	if match := multiParamPattern.FindStringSubmatch(remaining); match != nil {
		funcName := match[1]
		claimKey := match[2]
		paramsStr := match[3]

		// Parse parameters (backtick-quoted strings separated by commas)
		paramPattern := regexp.MustCompile("`([^`]*)`")
		paramMatches := paramPattern.FindAllStringSubmatch(paramsStr, -1)

		var params []string
		for _, paramMatch := range paramMatches {
			params = append(params, paramMatch[1])
		}

		if len(params) == 0 {
			return nil, fmt.Errorf("function %s requires at least one parameter", funcName)
		}

		p.pos += len(match[0])

		switch funcName {
		case "Contains":
			return Contains(claimKey, params...), nil
		case "OneOf":
			return OneOf(claimKey, params...), nil
		default:
			return nil, fmt.Errorf("unknown function: %s", funcName)
		}
	}

	return nil, fmt.Errorf("invalid function call at position %d: %s", p.pos, remaining)
}

func (p *ExpressionParser) peek() string {
	p.skipWhitespace()
	if p.pos >= p.length {
		return ""
	}

	remaining := p.input[p.pos:]

	if strings.HasPrefix(remaining, "||") {
		return "||"
	}
	if strings.HasPrefix(remaining, "&&") {
		return "&&"
	}
	if strings.HasPrefix(remaining, "!") {
		return "!"
	}
	if strings.HasPrefix(remaining, "(") {
		return "("
	}
	if strings.HasPrefix(remaining, ")") {
		return ")"
	}

	return ""
}

func (p *ExpressionParser) consume(expected string) error {
	p.skipWhitespace()
	if p.pos+len(expected) > p.length {
		return fmt.Errorf("expected '%s' at position %d", expected, p.pos)
	}

	actual := p.input[p.pos : p.pos+len(expected)]
	if actual != expected {
		return fmt.Errorf("expected '%s' but found '%s' at position %d", expected, actual, p.pos)
	}

	p.pos += len(expected)
	return nil
}

func (p *ExpressionParser) skipWhitespace() {
	for p.pos < p.length && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t' || p.input[p.pos] == '\n' || p.input[p.pos] == '\r') {
		p.pos++
	}
}
func extractClaimValue(claims jwt.MapClaims, claimKey string) (interface{}, error) {
	keys := strings.Split(claimKey, ".")
	var current interface{} = map[string]interface{}(claims)

	for i, k := range keys {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[k]; exists {
				current = val
			} else {
				return nil, fmt.Errorf("claim key '%s' not found at path '%s'", k, strings.Join(keys[:i+1], "."))
			}
		} else {
			return nil, fmt.Errorf("cannot traverse claim path at key '%s' (expected object, got %T)", k, current)
		}
	}

	return current, nil
}
