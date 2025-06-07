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
	"fmt"
	"github.com/shirou/gopsutil/v3/cpu"
)

type CPUInfo struct {
	Id    int     `json:"id"`
	Usage float64 `json:"usage"`
}

func (C CPUInfo) GetInfo() ([]CPUInfo, error) {
	// Get CPU usage stats
	percent, err := cpu.Percent(0, true)
	if err != nil {
		return []CPUInfo{}, fmt.Errorf("error")
	}
	cpus := []CPUInfo{}
	for i, p := range percent {
		cpuInfo := CPUInfo{
			Id:    i,
			Usage: p,
		}
		cpus = append(cpus, cpuInfo)
	}
	return cpus, nil
}

type Cpu interface {
	GetInfo() ([]CPUInfo, error)
}

func NewCPUInfo() Cpu {
	return CPUInfo{}
}
