// Copyright 2019 The gVisor Authors.
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

//go:build riscv64
// +build riscv64

package cpuid

import (
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// hostFeatureSet is initialized at startup.
//
// This is copied for HostFeatureSet, below.
var hostFeatureSet FeatureSet

// HostFeatureSet returns a copy of the host FeatureSet.
func HostFeatureSet() FeatureSet {
	return hostFeatureSet
}

// Fixed returns the same feature set.
func (fs FeatureSet) Fixed() FeatureSet {
	return fs
}

// Reads CPU information from host /proc/cpuinfo.
//
// Must run before syscall filter installation. This value is used to create
// the fake /proc/cpuinfo from a FeatureSet.
func initCPUInfo() {
	var hartid uint64
	if runtime.GOOS != "linux" {
		// Don't try to read Linux-specific /proc files or
		// warn about them not existing.
		return
	}
	cpuinfob, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		// Leave everything at 0, nothing can be done.
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	cpuinfo := string(cpuinfob)

	// We get the value straight from host /proc/cpuinfo.
	for _, line := range strings.Split(cpuinfo, "\n") {
		switch {
		case strings.Contains(line, "hart isa"):
			// skip hart isa
			continue
		case strings.Contains(line, "hart"):
			splitHart := strings.Split(line, ":")
			if len(splitHart) < 2 {
				hartid = uint64(len(hostFeatureSet.hartids))
				hostFeatureSet.hartids = append(hostFeatureSet.hartids, hartid)
				log.Warningf("Could not read /proc/cpuinfo: malformed hart")
				break
			}

			// assuming that we scan cpuinfo from top to bottom
			// we append the hartID to the slice 
			// so that we can print it out later
			hartid, err = strconv.ParseUint(strings.TrimSpace(splitHart[1]), 0, 64)
			if err != nil {
				// if fail, set to cpuid
				hartid = uint64(len(hostFeatureSet.hartids))
			}
			hostFeatureSet.hartids = append(hostFeatureSet.hartids, hartid)
		case strings.Contains(line, "isa"):
			splitISA := strings.Split(line, ":")
			if len(splitISA) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed isa")
				break
			}

			hostFeatureSet.isa = strings.TrimSpace(splitISA[1])
		case strings.Contains(line, "mmu"):
			splitMMU := strings.Split(line, ":")
			if len(splitMMU) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed mmu")
				break
			}
			
			hostFeatureSet.mmu = strings.TrimSpace(splitMMU[1])
		case strings.Contains(line, "mvendorid"):
			splitVendorid := strings.Split(line, ":")
			if len(splitVendorid) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed mvendorid")
				break
			}
			var err error
			hostFeatureSet.mvendorid, err = strconv.ParseUint(strings.TrimSpace(splitVendorid[1]), 0, 64)
			if err != nil {
				hostFeatureSet.mvendorid = 0
			}
		case strings.Contains(line, "marchid"):
			splitArchid := strings.Split(line, ":")
			if len(splitArchid) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed marchid")
				break
			}
			var err error
			hostFeatureSet.marchid, err = strconv.ParseUint(strings.TrimSpace(splitArchid[1]), 0, 64)
			if err != nil {
				hostFeatureSet.marchid = 0
			}
		case strings.Contains(line, "mimplid"):
			splitImplid := strings.Split(line, ":")
			if len(splitImplid) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed mimplid")
				break
			}
			var err error
			hostFeatureSet.mimplid, err = strconv.ParseUint(strings.TrimSpace(splitImplid[1]), 0, 64)
			if err != nil {
				hostFeatureSet.mimplid = 0
			}
		}
	}
}

// archInitialize initializes hostFeatureSet.
func archInitialize() {
	initCPUInfo()
	initHWCap()
}
