// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build loong64
// +build loong64

package cpuid

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// hostFeatureSet is initialized at startup and returned by HostFeatureSet.
var hostFeatureSet FeatureSet

// HostFeatureSet returns a copy of the host FeatureSet.
func HostFeatureSet() FeatureSet {
	return hostFeatureSet
}

// initCPUInfo populates hostFeatureSet from /proc/cpuinfo. On LoongArch the
// kernel prints fields like:
//
//	Model Name              : Loongson-3A5000
//	CPU MHz                 : 2500.00
//	BogoMIPS                : 5000.00
//	Features                : cpucfg lam ual fpu lsx lasx crc32
//
// Must run before the seccomp filter is installed.
func initCPUInfo() {
	if runtime.GOOS != "linux" {
		return
	}
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		switch key {
		case "Model Name":
			if hostFeatureSet.cpuModel == "" {
				hostFeatureSet.cpuModel = val
			}
		case "CPU MHz", "BogoMIPS":
			if hostFeatureSet.cpuFreqMHz != 0 {
				continue
			}
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				if key == "BogoMIPS" {
					v /= 2
				}
				hostFeatureSet.cpuFreqMHz = v
			}
		}
	}
}

// archInitialize initializes hostFeatureSet.
func archInitialize() {
	initCPUInfo()
	initHWCap()
}
