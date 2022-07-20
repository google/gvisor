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

//go:build amd64
// +build amd64

package cpuid

import (
	"io/ioutil"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

// cpuididFunction is a useful type wrapper. The format is eax | (ecx << 32).
type cpuidFunction uint64

func (f cpuidFunction) eax() uint32 {
	return uint32(f)
}

func (f cpuidFunction) ecx() uint32 {
	return uint32(f >> 32)
}

// The constants below are the lower or "standard" cpuid functions, ordered as
// defined by the hardware. Note that these may not be included in the standard
// set of functions that we are allowed to execute, which are filtered in the
// Native.Query function defined below.
const (
	vendorID                      cpuidFunction = 0x0               // Returns vendor ID and largest standard function.
	featureInfo                   cpuidFunction = 0x1               // Returns basic feature bits and processor signature.
	intelCacheDescriptors         cpuidFunction = 0x2               // Returns list of cache descriptors. Intel only.
	intelSerialNumber             cpuidFunction = 0x3               // Returns processor serial number (obsolete on new hardware). Intel only.
	intelDeterministicCacheParams cpuidFunction = 0x4               // Returns deterministic cache information. Intel only.
	monitorMwaitParams            cpuidFunction = 0x5               // Returns information about monitor/mwait instructions.
	powerParams                   cpuidFunction = 0x6               // Returns information about power management and thermal sensors.
	extendedFeatureInfo           cpuidFunction = 0x7               // Returns extended feature bits.
	_                                                               // Function 0x8 is reserved.
	intelDCAParams                cpuidFunction = 0x9               // Returns direct cache access information. Intel only.
	intelPMCInfo                  cpuidFunction = 0xa               // Returns information about performance monitoring features. Intel only.
	intelX2APICInfo               cpuidFunction = 0xb               // Returns core/logical processor topology. Intel only.
	_                                                               // Function 0xc is reserved.
	xSaveInfo                     cpuidFunction = 0xd               // Returns information about extended state management.
	xSaveInfoSub                  cpuidFunction = 0xd | (0x1 << 32) // Returns information about extended state management (Sub-leaf).
)

const xSaveInfoNumLeaves = 64 // Maximum number of xSaveInfo leaves.

// The "extended" functions.
const (
	extendedStart         cpuidFunction = 0x80000000
	extendedFunctionInfo  cpuidFunction = extendedStart + 0 // Returns highest available extended function in eax.
	extendedFeatures                    = extendedStart + 1 // Returns some extended feature bits in edx and ecx.
	processorBrandString2               = extendedStart + 2 // Processor Name String Identifier.
	processorBrandString3               = extendedStart + 3 // Processor Name String Identifier.
	processorBrandString4               = extendedStart + 4 // Processor Name String Identifier.
	l1CacheAndTLBInfo                   = extendedStart + 5 // Returns L2 cache information.
	l2CacheInfo                         = extendedStart + 6 // Returns L2 cache information.
	addressSizes                        = extendedStart + 8 // Physical and virtual address sizes.
)

var allowedBasicFunctions = [...]bool{
	vendorID:                      true,
	featureInfo:                   true,
	extendedFeatureInfo:           true,
	intelCacheDescriptors:         true,
	intelDeterministicCacheParams: true,
	xSaveInfo:                     true,
}

var allowedExtendedFunctions = [...]bool{
	extendedFunctionInfo - extendedStart:  true,
	extendedFeatures - extendedStart:      true,
	addressSizes - extendedStart:          true,
	processorBrandString2 - extendedStart: true,
	processorBrandString3 - extendedStart: true,
	processorBrandString4 - extendedStart: true,
	l1CacheAndTLBInfo - extendedStart:     true,
	l2CacheInfo - extendedStart:           true,
}

// Function executes a CPUID function.
//
// This is typically the native function or a Static definition.
type Function interface {
	Query(In) Out
}

// Native is a native Function.
//
// This implements Function.
type Native struct{}

// In is input to the Query function.
//
// +stateify savable
type In struct {
	Eax uint32
	Ecx uint32
}

// normalize drops irrelevant Ecx values.
func (i *In) normalize() {
	switch cpuidFunction(i.Eax) {
	case vendorID, featureInfo, intelCacheDescriptors, extendedFunctionInfo, extendedFeatures:
		i.Ecx = 0 // Ignore.
	case processorBrandString2, processorBrandString3, processorBrandString4, l1CacheAndTLBInfo, l2CacheInfo:
		i.Ecx = 0 // Ignore.
	case intelDeterministicCacheParams, extendedFeatureInfo:
		// Preserve i.Ecx.
	}
}

// Out is output from the Query function.
//
// +stateify savable
type Out struct {
	Eax uint32
	Ebx uint32
	Ecx uint32
	Edx uint32
}

// native is the native Query function.
func native(In) Out

// Query executes CPUID natively.
//
// This implements Function.
//
//go:nosplit
func (*Native) Query(in In) Out {
	if int(in.Eax) < len(allowedBasicFunctions) && allowedBasicFunctions[in.Eax] {
		return native(in)
	} else if in.Eax >= uint32(extendedStart) {
		if l := int(in.Eax - uint32(extendedStart)); l < len(allowedExtendedFunctions) && allowedExtendedFunctions[l] {
			return native(in)
		}
	}
	return Out{} // All zeros.
}

// query is a internal wrapper.
//
//go:nosplit
func (fs FeatureSet) query(fn cpuidFunction) (uint32, uint32, uint32, uint32) {
	out := fs.Query(In{Eax: fn.eax(), Ecx: fn.ecx()})
	return out.Eax, out.Ebx, out.Ecx, out.Edx
}

var hostFeatureSet FeatureSet

// HostFeatureSet returns a host CPUID.
//
//go:nosplit
func HostFeatureSet() FeatureSet {
	return hostFeatureSet
}

var (
	// cpuFreqMHz is the native CPU frequency.
	cpuFreqMHz float64
)

// Reads max cpu frequency from host /proc/cpuinfo. Must run before syscall
// filter installation. This value is used to create the fake /proc/cpuinfo
// from a FeatureSet.
func readMaxCPUFreq() {
	cpuinfob, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		// Leave it as 0... the VDSO bails out in the same way.
		log.Warningf("Could not read /proc/cpuinfo: %v", err)
		return
	}
	cpuinfo := string(cpuinfob)

	// We get the value straight from host /proc/cpuinfo. On machines with
	// frequency scaling enabled, this will only get the current value
	// which will likely be inaccurate. This is fine on machines with
	// frequency scaling disabled.
	for _, line := range strings.Split(cpuinfo, "\n") {
		if strings.Contains(line, "cpu MHz") {
			splitMHz := strings.Split(line, ":")
			if len(splitMHz) < 2 {
				log.Warningf("Could not read /proc/cpuinfo: malformed cpu MHz line")
				return
			}

			// If there was a problem, leave cpuFreqMHz as 0.
			var err error
			cpuFreqMHz, err = strconv.ParseFloat(strings.TrimSpace(splitMHz[1]), 64)
			if err != nil {
				log.Warningf("Could not parse cpu MHz value %v: %v", splitMHz[1], err)
				cpuFreqMHz = 0
				return
			}
			return
		}
	}
	log.Warningf("Could not parse /proc/cpuinfo, it is empty or does not contain cpu MHz")

}

func init() {
	hostFeatureSet = FeatureSet{
		Function: &Native{},
	}.Fixed()

	readMaxCPUFreq()
}
