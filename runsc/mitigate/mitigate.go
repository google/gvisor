// Copyright 2021 The gVisor Authors.
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

// Package mitigate provides libraries for the mitigate command. The
// mitigate command mitigates side channel attacks such as MDS. Mitigate
// shuts down CPUs via /sys/devices/system/cpu/cpu{N}/online.
package mitigate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// mds is the only bug we care about.
	mds = "mds"

	// Constants for parsing /proc/cpuinfo.
	processorKey  = "processor"
	vendorIDKey   = "vendor_id"
	cpuFamilyKey  = "cpu family"
	modelKey      = "model"
	physicalIDKey = "physical id"
	coreIDKey     = "core id"
	bugsKey       = "bugs"
)

// CPUSet contains a map of all CPUs on the system, mapped
// by Physical ID and CoreIDs. threads with the same
// Core and Physical ID are Hyperthread pairs.
type CPUSet []*CPU

// NewCPUSet creates a CPUSet from data read from /proc/cpuinfo.
func NewCPUSet(data string) (CPUSet, error) {
	// Each processor entry should start with the
	// processor key. Find the beginings of each.
	r := buildRegex(processorKey)
	indices := r.FindAllStringIndex(data, -1)

	if len(indices) < 1 {
		return nil, fmt.Errorf("no cpus found for: %q", data)
	}

	// Add the ending index for last entry.
	indices = append(indices, []int{len(data), -1})

	// Valid cpus are now defined by strings in between
	// indexes (e.g. data[index[i], index[i+1]]).
	// There should be len(indicies) - 1 CPUs
	// since the last index is the end of the string.
	var set CPUSet
	// Find each string that represents a CPU. These begin "processor".
	for i := 1; i < len(indices); i++ {
		start := indices[i-1][0]
		end := indices[i][0]
		// Parse the CPU entry, which should be between start/end.
		c, err := newCPU(data[start:end])
		if err != nil {
			return nil, err
		}
		set = append(set, c)
	}
	return set, nil
}

// IsVulnerable checks if this CPUSet is vulnerable to MDS.
func (c CPUSet) IsVulnerable() bool {
	for _, cpu := range c {
		if cpu.IsVulnerable() {
			return true
		}
	}
	return false
}

// String implements the String method for CPUSet.
func (c CPUSet) String() string {
	parts := make([]string, len(c))
	for i, cpu := range c {
		parts[i] = cpu.String()
	}
	return strings.Join(parts, "\n")
}

// CPU represents pertinent info about a single hyperthread in a pair.
type CPU struct {
	processorNumber int64               // the processor number of this CPU.
	vendorID        string              // the vendorID of CPU (e.g. AuthenticAMD).
	cpuFamily       int64               // CPU family number (e.g. 6 for CascadeLake/Skylake).
	model           int64               // CPU model number (e.g. 85 for CascadeLake/Skylake).
	physicalID      int64               // Physical ID of this CPU.
	coreID          int64               // Core ID of this CPU.
	bugs            map[string]struct{} // map of vulnerabilities parsed from the 'bugs' field.
}

func newCPU(data string) (*CPU, error) {
	processor, err := parseProcessor(data)
	if err != nil {
		return nil, err
	}

	vendorID, err := parseVendorID(data)
	if err != nil {
		return nil, err
	}

	cpuFamily, err := parseCPUFamily(data)
	if err != nil {
		return nil, err
	}

	model, err := parseModel(data)
	if err != nil {
		return nil, err
	}

	physicalID, err := parsePhysicalID(data)
	if err != nil {
		return nil, err
	}

	coreID, err := parseCoreID(data)
	if err != nil {
		return nil, err
	}

	bugs, err := parseBugs(data)
	if err != nil {
		return nil, err
	}

	return &CPU{
		processorNumber: processor,
		vendorID:        vendorID,
		cpuFamily:       cpuFamily,
		model:           model,
		physicalID:      physicalID,
		coreID:          coreID,
		bugs:            bugs,
	}, nil
}

// String implements the String method for CPU.
func (t *CPU) String() string {
	template := `%s: %d
%s: %s
%s: %d
%s: %d
%s: %d
%s: %d
%s: %s
`
	var bugs []string
	for bug := range t.bugs {
		bugs = append(bugs, bug)
	}

	return fmt.Sprintf(template,
		processorKey, t.processorNumber,
		vendorIDKey, t.vendorID,
		cpuFamilyKey, t.cpuFamily,
		modelKey, t.model,
		physicalIDKey, t.physicalID,
		coreIDKey, t.coreID,
		bugsKey, strings.Join(bugs, " "))
}

// IsVulnerable checks if a CPU is vulnerable to mds.
func (t *CPU) IsVulnerable() bool {
	_, ok := t.bugs[mds]
	return ok
}

// SimilarTo checks family/model/bugs fields for equality of two
// processors.
func (t *CPU) SimilarTo(other *CPU) bool {
	if t.vendorID != other.vendorID {
		return false
	}

	if other.cpuFamily != t.cpuFamily {
		return false
	}

	if other.model != t.model {
		return false
	}

	if len(other.bugs) != len(t.bugs) {
		return false
	}

	for bug := range t.bugs {
		if _, ok := other.bugs[bug]; !ok {
			return false
		}
	}
	return true
}

// parseProcessor grabs the processor field from /proc/cpuinfo output.
func parseProcessor(data string) (int64, error) {
	return parseIntegerResult(data, processorKey)
}

// parseVendorID grabs the vendor_id field from /proc/cpuinfo output.
func parseVendorID(data string) (string, error) {
	return parseRegex(data, vendorIDKey, `[\w\d]+`)
}

// parseCPUFamily grabs the cpu family field from /proc/cpuinfo output.
func parseCPUFamily(data string) (int64, error) {
	return parseIntegerResult(data, cpuFamilyKey)
}

// parseModel grabs the model field from /proc/cpuinfo output.
func parseModel(data string) (int64, error) {
	return parseIntegerResult(data, modelKey)
}

// parsePhysicalID parses the physical id field.
func parsePhysicalID(data string) (int64, error) {
	return parseIntegerResult(data, physicalIDKey)
}

// parseCoreID parses the core id field.
func parseCoreID(data string) (int64, error) {
	return parseIntegerResult(data, coreIDKey)
}

// parseBugs grabs the bugs field from /proc/cpuinfo output.
func parseBugs(data string) (map[string]struct{}, error) {
	result, err := parseRegex(data, bugsKey, `[\d\w\s]*`)
	if err != nil {
		return nil, err
	}
	bugs := strings.Split(result, " ")
	ret := make(map[string]struct{}, len(bugs))
	for _, bug := range bugs {
		ret[bug] = struct{}{}
	}
	return ret, nil
}

// parseIntegerResult parses fields expecting an integer.
func parseIntegerResult(data, key string) (int64, error) {
	result, err := parseRegex(data, key, `\d+`)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(result, 0, 64)
}

// buildRegex builds a regex for parsing each CPU field.
func buildRegex(key string) *regexp.Regexp {
	reg := fmt.Sprintf(`(?m)^%s\s*:\s*(.*)$`, key)
	return regexp.MustCompile(reg)
}

// parseRegex parses data with key inserted into a standard regex template.
func parseRegex(data, key, match string) (string, error) {
	r := buildRegex(key)
	matches := r.FindStringSubmatch(data)

	if len(matches) < 2 {
		return "", fmt.Errorf("failed to match key %q: %q", key, data)
	}
	return matches[1], nil
}
