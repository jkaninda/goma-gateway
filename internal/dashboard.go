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
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/sysinfo"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/shirou/gopsutil/v3/host"
	"io/fs"
	"log"
	"net/http"
	"runtime"
	"time"
)

type Uptime struct {
	Uptime float32 `json:"uptime"`
}
type DashboardConf struct {
	Routes      []Route      `json:"routes"`
	Middlewares []Middleware `json:"middlewares"`
}
type APIResponse struct {
}
type APIMiddleware struct {
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Paths []string    `json:"paths"`
	Rule  interface{} `json:"rule"`
}
type Overview struct {
	RouteTotal      int               `json:"routeTotal"`
	MiddlewareTotal int               `json:"middlewareTotal"`
	GoroutineTotal  int               `json:"goroutineTotal"`
	MemInfo         MemInfo           `json:"memInfo"`
	CpuInfo         []sysinfo.CPUInfo `json:"cpuInfo"`
	Uptime          string            `json:"uptime"`
	SysUptime       string            `json:"sysUptime"`
	Version         string            `json:"version"`
}

type MemInfo struct {
	MemTotal      string `json:"memTotal"`
	MemFree       string `json:"memFree"`
	MemTotalAlloc string `json:"memTotalAlloc"`
	MemAlloc      string `json:"memAlloc"`
	MemAvailable  string `json:"memAvailable"`
}
type CPUInfo struct {
	Usage float64 `json:"cpuUsage"`
}
type DashboardServer struct {
	server *http.Server
}

func NewDashboardServer(assets embed.FS) DashboardServer {
	router := mux.NewRouter()
	router.HandleFunc("/api/overview", overviewHandler).Methods("GET")
	router.HandleFunc("/api/routes", routeHandler).Methods("GET")
	router.HandleFunc("/api/middlewares", middlewareHandler).Methods("GET")
	serverRoot, err := fs.Sub(assets, "build")
	if err != nil {
		log.Fatal(err)
	}
	router.PathPrefix("/").Handler(http.StripPrefix("/", http.FileServer(http.FS(serverRoot))))
	return DashboardServer{&http.Server{
		Addr:         ":81",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	},
	}
}
func (apiServer DashboardServer) Serve() {
	logger.Info("Starting Dashboard server on 0.0.0.0:81")
	go func() {
		if err := apiServer.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("error starting Dashboard server %v", err)
		}
	}()
}
func overviewHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("api: %s %s for %s %s", r.Method, r.URL.Path, getRealIP(r), r.UserAgent())
	uptimeSeconds, err := host.Uptime()
	if err != nil {
		logger.Error("Error fetching uptime: %v", err)
	}
	// Convert seconds to a more readable format
	uptime := time.Duration(uptimeSeconds) * time.Second
	appUptime := time.Since(startTime)
	memInfo := sysinfo.NewMemInfo()
	_, memStats := memInfo.GetInfo()
	cpuInfo := sysinfo.NewCPUInfo()
	_, cpus := cpuInfo.GetInfo()

	goroutineTotal := runtime.NumGoroutine()

	ov := Overview{
		RouteTotal:      len(dynamicRoutes),
		MiddlewareTotal: len(dynamicMiddlewares),
		GoroutineTotal:  goroutineTotal,
		MemInfo: MemInfo{
			MemTotal:      util.ConvertBytes(memStats.MemTotal),
			MemFree:       util.ConvertBytes(memStats.MemFree),
			MemAvailable:  util.ConvertBytes(memStats.MemAvailable),
			MemAlloc:      util.ConvertBytes(memStats.MemAlloc),
			MemTotalAlloc: util.ConvertBytes(memStats.MemTotalAlloc),
		},
		CpuInfo:   cpus,
		Uptime:    fmt.Sprintf("%v", appUptime),
		SysUptime: fmt.Sprintf("%v", uptime),
		Version:   util.Version,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(ov)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
func routeHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("api: %s %s for %s %s", r.Method, r.URL.Path, getRealIP(r), r.UserAgent())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(dynamicRoutes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
func middlewareHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("api: %s %s for %s %s", r.Method, r.URL.Path, getRealIP(r), r.UserAgent())
	apiMiddlewares := []APIMiddleware{}
	for _, m := range dynamicMiddlewares {
		apiMiddlewares = append(apiMiddlewares, APIMiddleware{
			Name:  m.Name,
			Type:  m.Type,
			Paths: m.Paths,
			Rule:  "***",
		})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(apiMiddlewares)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
