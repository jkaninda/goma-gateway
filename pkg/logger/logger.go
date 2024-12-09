package logger

/*
/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/jkaninda/goma-gateway/util"
)

// Generic logging function
func logMessage(level, defaultOutput, msg string, args ...interface{}) {
	logLevel := getLogLevel()
	if shouldLog(level, logLevel) {
		log.SetOutput(getStd(util.GetStringEnv("GOMA_ACCESS_LOG", defaultOutput)))
		logWithCaller(level, msg, args...)
	}
}

// Info logs informational messages
func Info(msg string, args ...interface{}) {
	logMessage("INFO", "/dev/stdout", msg, args...)
}

// Warn logs warning messages
func Warn(msg string, args ...interface{}) {
	logMessage("WARN", "/dev/stdout", msg, args...)
}

// Error logs error messages
func Error(msg string, args ...interface{}) {
	logMessage("ERROR", "/dev/stderr", msg, args...)
}

// Fatal logs fatal errors and exits the program
func Fatal(msg string, args ...interface{}) {
	log.SetOutput(os.Stdout)
	logWithCaller("ERROR", msg, args...)
	os.Exit(1)
}

// Debug logs debug messages
func Debug(msg string, args ...interface{}) {
	logMessage("DEBUG", "/dev/stdout", msg, args...)
}

// Trace logs trace messages
func Trace(msg string, args ...interface{}) {
	logMessage("TRACE", "/dev/stdout", msg, args...)
}

// Determines whether the message should be logged based on log level
func shouldLog(level, currentLevel string) bool {
	levelOrder := map[string]int{
		"trace": 1,
		"debug": 2,
		"info":  3,
		"warn":  4,
		"error": 5,
		"off":   6,
	}

	current := strings.ToLower(currentLevel)
	target := strings.ToLower(level)

	return levelOrder[target] >= levelOrder[current]
}

// Helper function to format and log messages with file and line number
func logWithCaller(level, msg string, args ...interface{}) {
	// Format message if there are additional arguments
	formattedMessage := msg
	if len(args) > 0 {
		formattedMessage = fmt.Sprintf(msg, args...)
	}

	// Get the caller's file and line number (skip 2 frames)
	_, file, line, ok := runtime.Caller(2)
	if !ok {
		file = "unknown"
		line = 0
	}

	if getLogLevel() == traceLog {
		log.Printf("%s: %s (File: %s, Line: %d)\n", level, formattedMessage, file, line)
	} else {
		log.Printf("%s: %s\n", level, formattedMessage)
	}
}

// Determines the appropriate standard output based on the environment variable
func getStd(out string) *os.File {
	switch out {
	case "/dev/stdout":
		return os.Stdout
	case "/dev/stderr":
		return os.Stderr
	case "/dev/stdin":
		return os.Stdin
	default:
		return os.Stdout
	}
}

// Retrieves the current log level from environment variables
func getLogLevel() string {
	return strings.ToLower(util.GetStringEnv("GOMA_LOG_LEVEL", ""))
}
