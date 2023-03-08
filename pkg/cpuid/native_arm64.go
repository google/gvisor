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

//go:build arm64
// +build arm64

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
		case strings.Contains(line, "BogoMIPS"):
			splitMHz := strings.Split(line, ":")
			if len(splitMHz) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed BogoMIPS")
				break
			}

			// If there was a problem, leave cpuFreqMHz as 0.
			var err error
			hostFeatureSet.cpuFreqMHz, err = strconv.ParseFloat(strings.TrimSpace(splitMHz[1]), 64)
			if err != nil {
				hostFeatureSet.cpuFreqMHz = 0.0
				log.Warningf("Could not parse BogoMIPS value %v: %v", splitMHz[1], err)
			}
		case strings.Contains(line, "CPU implementer"):
			splitImpl := strings.Split(line, ":")
			if len(splitImpl) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU implementer")
				break
			}

			// If there was a problem, leave cpuImplHex as 0.
			var err error
			hostFeatureSet.cpuImplHex, err = strconv.ParseUint(strings.TrimSpace(splitImpl[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuImplHex = 0
				log.Warningf("Could not parse CPU implementer value %v: %v", splitImpl[1], err)
			}
		case strings.Contains(line, "CPU architecture"):
			splitArch := strings.Split(line, ":")
			if len(splitArch) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU architecture")
				break
			}

			// If there was a problem, leave cpuArchDec as 0.
			var err error
			hostFeatureSet.cpuArchDec, err = strconv.ParseUint(strings.TrimSpace(splitArch[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuArchDec = 0
				log.Warningf("Could not parse CPU architecture value %v: %v", splitArch[1], err)
			}
		case strings.Contains(line, "CPU variant"):
			splitVar := strings.Split(line, ":")
			if len(splitVar) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU variant")
				break
			}

			// If there was a problem, leave cpuVarHex as 0.
			var err error
			hostFeatureSet.cpuVarHex, err = strconv.ParseUint(strings.TrimSpace(splitVar[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuVarHex = 0
				log.Warningf("Could not parse CPU variant value %v: %v", splitVar[1], err)
			}
		case strings.Contains(line, "CPU part"):
			splitPart := strings.Split(line, ":")
			if len(splitPart) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU part")
				break
			}

			// If there was a problem, leave cpuPartHex as 0.
			var err error
			hostFeatureSet.cpuPartHex, err = strconv.ParseUint(strings.TrimSpace(splitPart[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuPartHex = 0
				log.Warningf("Could not parse CPU part value %v: %v", splitPart[1], err)
			}
		case strings.Contains(line, "CPU revision"):
			splitRev := strings.Split(line, ":")
			if len(splitRev) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed CPU revision")
				break
			}

			// If there was a problem, leave cpuRevDec as 0.
			var err error
			hostFeatureSet.cpuRevDec, err = strconv.ParseUint(strings.TrimSpace(splitRev[1]), 0, 64)
			if err != nil {
				hostFeatureSet.cpuRevDec = 0
				log.Warningf("Could not parse CPU revision value %v: %v", splitRev[1], err)
			}
		}
	}
}

// archInitialize initializes hostFeatureSet.
func archInitialize() {
	initCPUInfo()
	initHWCap()
}
