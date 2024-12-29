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

package sysinfo

import (
	"runtime"
)

type MemInfo struct {
	MemTotal      uint64 `json:"memTotal"`
	MemTotalAlloc uint64 `json:"memTotalAlloc"`
	MemAlloc      uint64 `json:"memAlloc"`
	MemFree       uint64 `json:"memFree"`
	MemAvailable  uint64 `json:"memAvailable"`
}

func (m MemInfo) GetInfo() (error, MemInfo) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return nil, MemInfo{
		MemTotal:      memStats.Sys,
		MemTotalAlloc: memStats.TotalAlloc,
		MemFree:       memStats.Frees,
		MemAlloc:      memStats.Alloc,
		MemAvailable:  memStats.Sys - memStats.Alloc,
	}
}

func NewMemInfo() Memory {
	return &MemInfo{}
}

type Memory interface {
	GetInfo() (error, MemInfo)
}
