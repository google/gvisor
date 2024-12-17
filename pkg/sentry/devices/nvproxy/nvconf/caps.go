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

package nvconf

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// DriverCaps is a set of NVIDIA driver capabilities as a bitmask.
type DriverCaps uint8

// Individual NVIDIA driver capabilities.
const (
	CapCompute DriverCaps = 1 << iota
	CapDisplay
	CapGraphics
	CapNGX
	CapUtility
	CapVideo
	CapCompat32
	numValidCaps int = iota
)

const (
	// AllCapabilitiesName is a special capability name
	// that can be used to represent all capabilities.
	AllCapabilitiesName = "all"

	// ValidCapabilities is the set of all valid capabilities.
	ValidCapabilities = DriverCaps(1<<numValidCaps - 1)

	// SupportedDriverCaps is the set of driver capabilities that are supported by
	// nvproxy. Similar to
	// nvidia-container-toolkit/internal/config/image/capabilities.go:SupportedDriverCapabilities.
	SupportedDriverCaps = DriverCaps(CapCompute | CapUtility | CapGraphics)

	// DefaultDriverCaps is the set of driver capabilities that are enabled by
	// default in the absence of any other configuration. See
	// nvidia-container-toolkit/internal/config/image/capabilities.go:DefaultDriverCapabilities.
	DefaultDriverCaps = DriverCaps(CapCompute | CapUtility)
)

// individualString returns the string representation of the given capability.
// It must be one of the individual capabilities, or this will panic.
func (c DriverCaps) individualString() string {
	switch c {
	case CapCompute:
		return "compute"
	case CapDisplay:
		return "display"
	case CapGraphics:
		return "graphics"
	case CapNGX:
		return "ngx"
	case CapUtility:
		return "utility"
	case CapVideo:
		return "video"
	case CapCompat32:
		return "compat32"
	default:
		panic(fmt.Sprintf("capability has no string mapping: %x", uint8(c)))
	}
}

// individualNVIDIAFlag returns the flag that can be passed to
// nvidia-container-cli to enable the given capability.
// See nvidia-container-toolkit/blob/main/cmd/nvidia-container-runtime-hook/capabilities.go:capabilityToCLI
func (c DriverCaps) individualNVIDIAFlag() string {
	switch c {
	case CapCompute, CapDisplay, CapGraphics, CapNGX, CapUtility, CapVideo, CapCompat32:
		return fmt.Sprintf("--%s", c.individualString())
	default:
		panic(fmt.Sprintf("capability has no NVIDIA flag mapping: %x", uint8(c)))
	}
}

// individualCapabilityFromString returns the individual capability for the
// given string.
func individualCapabilityFromString(capName string) (DriverCaps, bool) {
	for i := 0; i < numValidCaps; i++ {
		cap := DriverCaps(1 << i)
		if cap.String() == capName {
			return cap, true
		}
	}
	return 0, false
}

// DriverCapsFromString creates a new capability set from the given
// comma-separated list of capability names.
// The returned boolean represents whether the "all" keyword was used.
// Note that the "all" keyword is not actually expanded into the set of
// capabilities returned here; it is up to the caller to decide how to
// handle it.
func DriverCapsFromString(commaSeparatedCaps string) (DriverCaps, bool, error) {
	cs := DriverCaps(0)
	hasAll := false
	for _, capName := range strings.Split(commaSeparatedCaps, ",") {
		capName = strings.TrimSpace(capName)
		if capName == "" {
			continue
		}
		if capName == AllCapabilitiesName {
			hasAll = true
			continue
		}
		cap, ok := individualCapabilityFromString(capName)
		if !ok {
			return 0, false, fmt.Errorf("invalid capability: %q", capName)
		}
		cs |= DriverCaps(cap)
	}
	return cs, hasAll, nil
}

// String returns the string representation of the capability set.
func (c DriverCaps) String() string {
	if c == 0 {
		return ""
	}
	firstCap := true
	var sb strings.Builder
	for i := 0; i < numValidCaps; i++ {
		cap := DriverCaps(1 << i)
		if c&cap != 0 {
			if !firstCap {
				sb.WriteString(",")
			}
			firstCap = false
			sb.WriteString(cap.individualString())
		}
	}
	return sb.String()
}

// NVIDIAFlags returns the nvidia-container-cli flags that can be passed to
// enable the capabilities in the set.
func (c DriverCaps) NVIDIAFlags() []string {
	if c == 0 {
		return nil
	}
	caps := make([]string, 0, numValidCaps)
	for i := 0; i < numValidCaps; i++ {
		cap := DriverCaps(1 << i)
		if c&cap != 0 {
			caps = append(caps, cap.individualNVIDIAFlag())
		}
	}
	return caps
}

// PopularCapabilitySets returns the most commonly used capability sets.
func PopularCapabilitySets() []DriverCaps {
	capSets := make(map[DriverCaps]struct{})
	capSets[SupportedDriverCaps] = struct{}{}
	capSets[DefaultDriverCaps] = struct{}{}
	// Add every individual supported capability together with CapUtility.
	for i := 0; i < numValidCaps; i++ {
		cap := DriverCaps(1 << i)
		if cap == CapUtility {
			continue
		}
		if cap&SupportedDriverCaps == 0 {
			continue
		}
		capSets[cap|CapUtility] = struct{}{}
	}
	// Return as a sorted list.
	return slices.Sorted(maps.Keys(capSets))
}
