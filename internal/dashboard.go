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
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/sysinfo"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/shirou/gopsutil/v3/host"
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
	RouteCnt      int               `json:"routeCnt"`
	MiddlewareCnt int               `json:"middlewareCnt"`
	GoroutineCnt  int               `json:"goroutineCnt"`
	MemInfo       MemInfo           `json:"memInfo"`
	CpuInfo       []sysinfo.CPUInfo `json:"cpuInfo"`
	Uptime        string            `json:"uptime"`
	SysUptime     string            `json:"sysUptime"`
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

func NewServer() {
	router := mux.NewRouter()
	router.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	router.HandleFunc("/api/overview", overviewHandler).Methods("GET")
	router.HandleFunc("/api/routes", routeHandler).Methods("GET")
	router.HandleFunc("/api/middlewares", middlewareHandler).Methods("GET")
	go func() {
		err := http.ListenAndServe(":81", router)
		if err != nil {
			logger.Fatal("error starting server %v", err)
			return
		}
	}()

}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("Hello, World!"))
	if err != nil {
		return
	}

}
func overviewHandler(w http.ResponseWriter, r *http.Request) {
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

	goroutineCnt := runtime.NumGoroutine()

	ov := Overview{
		RouteCnt:      len(dynamicRoutes),
		MiddlewareCnt: len(dynamicMiddlewares),
		GoroutineCnt:  goroutineCnt,
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
	}
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(ov)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
func routeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(dynamicRoutes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
func middlewareHandler(w http.ResponseWriter, r *http.Request) {
	apiMiddlewares := []APIMiddleware{}
	for _, m := range dynamicMiddlewares {
		apiMiddlewares = append(apiMiddlewares, APIMiddleware{
			Name:  m.Name,
			Type:  m.Type,
			Paths: m.Paths,
			Rule:  "***",
		})
	}
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(apiMiddlewares)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
