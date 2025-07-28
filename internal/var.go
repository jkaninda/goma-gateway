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
	"github.com/jkaninda/goma-gateway/internal/certmanager"
	"github.com/jkaninda/goma-gateway/internal/metrics"
	logger2 "github.com/jkaninda/logger"
	"os"
	"time"
)

var (
	counter            uint32
	dynamicRoutes      []Route
	dynamicMiddlewares []Middleware
	redisBased         = false
	stopChan           = make(chan struct{})
	reloaded           = false
	webAddress         = "[::]:8080"
	webSecureAddress   = "[::]:8443"
	logger             = logger2.Default()
	certManager        *certmanager.CertManager
	cachedDialer       = NewCachedDialer(5 * time.Minute)
	shutdownChan       = make(chan os.Signal, 1)
	processStartTime   = time.Now()
	prometheusMetrics  = metrics.NewPrometheusMetrics(processStartTime, shutdownChan)
	debugMode          = false
)
