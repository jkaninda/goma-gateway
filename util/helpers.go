package util

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"github.com/robfig/cron/v3"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FileExists checks if the file does exist
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// FolderExists checks if the folder does exist
func FolderExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()

}
func GetStringEnv(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val
}

func GetIntEnv(key string, defaultValue int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue

	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue

	}
	return i

}
func GetBoolEnv(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue

	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultValue
	}
	return b

}

// SetEnv Set env
func SetEnv(name, value string) {
	if len(value) != 0 {
		err := os.Setenv(name, value)
		if err != nil {
			return
		}
	}

}
func MergeSlices(slice1, slice2 []string) []string {
	return append(slice1, slice2...)
}

// ParseURLPath returns a URL path
func ParseURLPath(urlPath string) string {
	// Replace any double slashes with a single slash
	urlPath = strings.ReplaceAll(urlPath, "//", "/")

	// Ensure the path starts with a single leading slash
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	return urlPath
}

func ParseRoutePath(path, blockedPath string) string {
	basePath := ParseURLPath(path)
	switch {
	case blockedPath == "":
		return basePath
	case strings.HasSuffix(blockedPath, "/*"):
		return basePath + blockedPath[:len(blockedPath)-2]
	case strings.HasSuffix(blockedPath, "*"):
		return basePath + blockedPath[:len(blockedPath)-1]
	default:
		return basePath + blockedPath
	}
}

func UrlParsePath(uri string) string {
	parse, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return parse.Path
}

func HasWhitespace(s string) bool {
	return regexp.MustCompile(`\s`).MatchString(s)
}

// IsValidCronExpression verify cronExpression and returns boolean
func IsValidCronExpression(cronExpr string) bool {
	// Parse the cron expression
	_, err := cron.ParseStandard(cronExpr)
	return err == nil
}

func ParseDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return 0, err
	}
	return duration, nil
}

func Slug(text string) string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Replace spaces and special characters with hyphens
	re := regexp.MustCompile(`[^\w]+`)
	text = re.ReplaceAllString(text, "-")

	// Remove leading and trailing hyphens
	text = strings.Trim(text, "-")

	return text
}
