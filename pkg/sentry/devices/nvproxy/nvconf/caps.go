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

import "strings"

// DriverCap is a GPU driver capability (like compute, graphics, etc.).
type DriverCap string

// Driver capabilities understood by nvproxy.
const (
	// AllCap is a special value that means all supported driver capabilities.
	AllCap DriverCap = "all"

	Compat32Cap DriverCap = "compat32"
	ComputeCap  DriverCap = "compute"
	DisplayCap  DriverCap = "display"
	GraphicsCap DriverCap = "graphics"
	NGXCap      DriverCap = "ngx"
	UtilityCap  DriverCap = "utility"
	VideoCap    DriverCap = "video"
)

// ToFlag converts the driver capability to a flag for nvidia-container-cli.
// See nvidia-container-toolkit/cmd/nvidia-container-runtime-hook/capabilities.go:capabilityToCLI().
func (c DriverCap) ToFlag() string {
	return "--" + string(c)
}

// DriverCaps is a set of GPU driver capabilities.
type DriverCaps map[DriverCap]struct{}

// DefaultDriverCaps is the set of driver capabilities that are enabled by
// default in the absence of any other configuration. See
// nvidia-container-toolkit/internal/config/image/capabilities.go:DefaultDriverCapabilities.
var DefaultDriverCaps = DriverCaps{
	ComputeCap: struct{}{},
	UtilityCap: struct{}{},
}

// SupportedDriverCaps is the set of driver capabilities that are supported by
// nvproxy. Similar to
// nvidia-container-toolkit/internal/config/image/capabilities.go:SupportedDriverCapabilities.
var SupportedDriverCaps = DriverCaps{
	ComputeCap: struct{}{},
	UtilityCap: struct{}{},
}

// KnownDriverCapValues is the set of understood driver capability values.
var KnownDriverCapValues = DriverCaps{
	Compat32Cap: struct{}{},
	ComputeCap:  struct{}{},
	DisplayCap:  struct{}{},
	GraphicsCap: struct{}{},
	NGXCap:      struct{}{},
	UtilityCap:  struct{}{},
	VideoCap:    struct{}{},
}

// DriverCapsFromString constructs NvidiaDriverCaps from a comma-separated list
// of driver capabilities.
func DriverCapsFromString(caps string) DriverCaps {
	res := make(DriverCaps)
	for _, cap := range strings.Split(caps, ",") {
		trimmed := strings.TrimSpace(cap)
		if len(trimmed) == 0 {
			continue
		}
		res[DriverCap(trimmed)] = struct{}{}
	}
	return res
}

// HasAll returns true if the set of driver capabilities contains "all".
func (c DriverCaps) HasAll() bool {
	_, ok := c[AllCap]
	return ok
}

// Intersect returns the intersection of two sets of driver capabilities.
func (c DriverCaps) Intersect(c2 DriverCaps) DriverCaps {
	if c2.HasAll() {
		return c
	}
	if c.HasAll() {
		return c2
	}
	res := make(DriverCaps)
	for cap := range c2 {
		if _, ok := c[cap]; ok {
			res[cap] = struct{}{}
		}
	}
	return res
}
