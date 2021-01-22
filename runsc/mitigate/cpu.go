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

package mitigate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// constants of coomm
	meltdown = "cpu_meltdown"
	l1tf     = "l1tf"
	mds      = "mds"
	swapgs   = "swapgs"
	taa      = "taa"
)

const (
	processorKey = "processor"
	vendorIDKey  = "vendor_id"
	cpuFamilyKey = "cpu family"
	modelKey     = "model"
	coreIDKey    = "core id"
	bugsKey      = "bugs"
)

// getCPUSet returns cpu structs from reading /proc/cpuinfo.
func getCPUSet(data string) ([]*cpu, error) {
	// Each processor entry should start with the
	// processor key. Find the beginings of each.
	r := buildRegex(processorKey, `\d+`)
	indices := r.FindAllStringIndex(data, -1)
	if len(indices) < 1 {
		return nil, fmt.Errorf("no cpus found for: %s", data)
	}

	// Add the ending index for last entry.
	indices = append(indices, []int{len(data), -1})

	// Valid cpus are now defined by strings in between
	// indexes (e.g. data[index[i], index[i+1]]).
	// There should be len(indicies) - 1 CPUs
	// since the last index is the end of the string.
	var cpus = make([]*cpu, 0, len(indices)-1)
	// Find each string that represents a CPU. These begin "processor".
	for i := 1; i < len(indices); i++ {
		start := indices[i-1][0]
		end := indices[i][0]
		// Parse the CPU entry, which should be between start/end.
		c, err := getCPU(data[start:end])
		if err != nil {
			return nil, err
		}
		cpus = append(cpus, c)
	}
	return cpus, nil
}

// type cpu represents pertinent info about a cpu.
type cpu struct {
	processorNumber int64               // the processor number of this CPU.
	vendorID        string              // the vendorID of CPU (e.g. AuthenticAMD).
	cpuFamily       int64               // CPU family number (e.g. 6 for CascadeLake/Skylake).
	model           int64               // CPU model number (e.g. 85 for CascadeLake/Skylake).
	coreID          int64               // This CPU's core id to match Hyperthread Pairs
	bugs            map[string]struct{} // map of vulnerabilities parsed from the 'bugs' field.
}

// getCPU parses a CPU from a single cpu entry from /proc/cpuinfo.
func getCPU(data string) (*cpu, error) {
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

	coreID, err := parseCoreID(data)
	if err != nil {
		return nil, err
	}

	bugs, err := parseBugs(data)
	if err != nil {
		return nil, err
	}

	return &cpu{
		processorNumber: processor,
		vendorID:        vendorID,
		cpuFamily:       cpuFamily,
		model:           model,
		coreID:          coreID,
		bugs:            bugs,
	}, nil
}

// List of pertinent side channel vulnerablilites.
// For mds, see: https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html.
var vulnerabilities = []string{
	meltdown,
	l1tf,
	mds,
	swapgs,
	taa,
}

// isVulnerable checks if a CPU is vulnerable to pertinent bugs.
func (c *cpu) isVulnerable() bool {
	for _, bug := range vulnerabilities {
		if _, ok := c.bugs[bug]; ok {
			return true
		}
	}
	return false
}

// similarTo checks family/model/bugs fields for equality of two
// processors.
func (c *cpu) similarTo(other *cpu) bool {
	if c.vendorID != other.vendorID {
		return false
	}

	if other.cpuFamily != c.cpuFamily {
		return false
	}

	if other.model != c.model {
		return false
	}

	if len(other.bugs) != len(c.bugs) {
		return false
	}

	for bug := range c.bugs {
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
func buildRegex(key, match string) *regexp.Regexp {
	reg := fmt.Sprintf(`(?m)^%s\s*:\s*(.*)$`, key)
	return regexp.MustCompile(reg)
}

// parseRegex parses data with key inserted into a standard regex template.
func parseRegex(data, key, match string) (string, error) {
	r := buildRegex(key, match)
	matches := r.FindStringSubmatch(data)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to match key %s: %s", key, data)
	}
	return matches[1], nil
}
