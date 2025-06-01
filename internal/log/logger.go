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

package log

import (
	"github.com/jkaninda/goma-gateway/util"
	"github.com/jkaninda/logger"
	"strings"
)

func InitLogger() *logger.Logger {
	logFile := util.GetStringEnv("GOMA_LOG_FILE", "")
	logFormat := util.GetStringEnv("GOMA_LOG_FORMAT", "text")
	level := strings.ToLower(util.GetStringEnv("GOMA_LOG_LEVEL", "ERROR"))

	// Use default logger when all defaults are in place
	if logFile == "" && logFormat == "text" && (level == "" || level == "info") {
		return logger.Default()
	}

	l := logger.New()

	// Configure output file
	if logFile != "" {
		l = l.WithOptions(logger.WithOutputFile(logFile))
	}

	// Configure log level
	switch level {
	case "trace", "debug":
		l = l.WithOptions(logger.WithDebugLevel(), logger.WithCaller())
	case "info":
		l = l.WithOptions(logger.WithInfoLevel())
	case "warn":
		l = l.WithOptions(logger.WithWarningLevel())
	case "error":
		l = l.WithOptions(logger.WithErrorLevel())
	case "off":
		l = l.WithOptions(logger.WithLevelOff())
	default:
		l = l.WithOptions(logger.WithInfoLevel())
	}

	// Configure format
	if logFormat == "json" {
		l = l.WithOptions(logger.WithJSONFormat())
	}
	return l
}
