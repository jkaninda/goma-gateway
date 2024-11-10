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

	"github.com/jkaninda/goma-gateway/util"
)

type Logger struct {
	msg  string
	args interface{}
}

// Info returns info log
func Info(msg string, args ...interface{}) {
	log.SetOutput(getStd(util.GetStringEnv("GOMA_ACCESS_LOG", "/dev/stdout")))
	formattedMessage := fmt.Sprintf(msg, args...)
	if len(args) == 0 {
		log.Printf("INFO: %s\n", msg)
	} else {
		log.Printf("INFO: %s\n", formattedMessage)
	}
}

// Warn returns warning log
func Warn(msg string, args ...interface{}) {
	log.SetOutput(getStd(util.GetStringEnv("GOMA_ACCESS_LOG", "/dev/stdout")))
	formattedMessage := fmt.Sprintf(msg, args...)
	if len(args) == 0 {
		log.Printf("WARN: %s\n", msg)
	} else {
		log.Printf("WARN: %s\n", formattedMessage)
	}
}

// Error logs error messages
func Error(msg string, args ...interface{}) {
	log.SetOutput(getStd(util.GetStringEnv("GOMA_ERROR_LOG", "/dev/stderr")))
	logWithCaller("ERROR", msg, args...)
}

func Fatal(msg string, args ...interface{}) {
	log.SetOutput(os.Stdout)
	formattedMessage := fmt.Sprintf(msg, args...)
	if len(args) == 0 {
		log.Printf("ERROR: %s\n", msg)
	} else {
		log.Printf("ERROR: %s\n", formattedMessage)
	}

	os.Exit(1)
}

func Debug(msg string, args ...interface{}) {
	log.SetOutput(getStd(util.GetStringEnv("GOMA_ACCESS_LOG", "/dev/stdout")))
	logWithCaller("DEBUG", msg, args...)

}

// Helper function to format and log messages with file and line number
func logWithCaller(level, msg string, args ...interface{}) {
	formattedMessage := fmt.Sprintf(msg, args...)
	_, file, line, ok := runtime.Caller(2) // Get the caller's file and line number (skip 2 frames)

	if !ok {
		file = "unknown"
		line = 0
	}

	if len(args) == 0 {
		log.Printf("%s: %s (File: %s, Line: %d)\n", level, msg, file, line)
	} else {
		log.Printf("%s: %s (File: %s, Line: %d)\n", level, formattedMessage, file, line)
	}
}

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
