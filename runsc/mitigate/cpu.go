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
	"io/ioutil"
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
	processorKey  = "processor"
	vendorIDKey   = "vendor_id"
	cpuFamilyKey  = "cpu family"
	modelKey      = "model"
	physicalIDKey = "physical id"
	coreIDKey     = "core id"
	bugsKey       = "bugs"
)

const (
	cpuOnlineTemplate = "/sys/devices/system/cpu/cpu%d/online"
)

// cpuSet contains a map of all CPUs on the system, mapped
// by Physical ID and CoreIDs. threads with the same
// Core and Physical ID are Hyperthread pairs.
type cpuSet map[cpuID]*threadGroup

// newCPUSet creates a CPUSet from data read from /proc/cpuinfo.
func newCPUSet(data []byte, vulnerable func(*thread) bool) (cpuSet, error) {
	processors, err := getThreads(string(data))
	if err != nil {
		return nil, err
	}

	set := make(cpuSet)
	for _, p := range processors {
		// Each ID is of the form physicalID:coreID. Hyperthread pairs
		// have identical physical and core IDs. We need to match
		// Hyperthread pairs so that we can shutdown all but one per
		// pair.
		core, ok := set[p.id]
		if !ok {
			core = &threadGroup{}
			set[p.id] = core
		}
		core.isVulnerable = core.isVulnerable || vulnerable(p)
		core.threads = append(core.threads, p)
	}
	return set, nil
}

// String implements the String method for CPUSet.
func (c cpuSet) String() string {
	ret := ""
	for _, tg := range c {
		ret += fmt.Sprintf("%s\n", tg)
	}
	return ret
}

// getRemainingList returns the list of threads that will remain active
// after mitigation.
func (c cpuSet) getRemainingList() []*thread {
	threads := make([]*thread, 0, len(c))
	for _, core := range c {
		// If we're vulnerable, take only one thread from the pair.
		if core.isVulnerable {
			threads = append(threads, core.threads[0])
			continue
		}
		// Otherwise don't shutdown anything.
		threads = append(threads, core.threads...)
	}
	return threads
}

// getShutdownList returns the list of threads that will be shutdown on
// mitigation.
func (c cpuSet) getShutdownList() []*thread {
	threads := make([]*thread, 0)
	for _, core := range c {
		// Only if we're vulnerable do shutdown anything. In this case,
		// shutdown all but the first entry.
		if core.isVulnerable && len(core.threads) > 1 {
			threads = append(threads, core.threads[1:]...)
		}
	}
	return threads
}

// threadGroup represents Hyperthread pairs on the same physical/core ID.
type threadGroup struct {
	threads      []*thread
	isVulnerable bool
}

// String implements the String method for threadGroup.
func (c *threadGroup) String() string {
	ret := fmt.Sprintf("ThreadGroup:\nIsVulnerable: %t\n", c.isVulnerable)
	for _, processor := range c.threads {
		ret += fmt.Sprintf("%s\n", processor)
	}
	return ret
}

// getThreads returns threads structs from reading /proc/cpuinfo.
func getThreads(data string) ([]*thread, error) {
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
	var cpus = make([]*thread, 0, len(indices)-1)
	// Find each string that represents a CPU. These begin "processor".
	for i := 1; i < len(indices); i++ {
		start := indices[i-1][0]
		end := indices[i][0]
		// Parse the CPU entry, which should be between start/end.
		c, err := newThread(data[start:end])
		if err != nil {
			return nil, err
		}
		cpus = append(cpus, c)
	}
	return cpus, nil
}

// cpuID for each thread is defined by the physical and
// core IDs. If equal, two threads are Hyperthread pairs.
type cpuID struct {
	physicalID int64
	coreID     int64
}

// type cpu represents pertinent info about a cpu.
type thread struct {
	processorNumber int64               // the processor number of this CPU.
	vendorID        string              // the vendorID of CPU (e.g. AuthenticAMD).
	cpuFamily       int64               // CPU family number (e.g. 6 for CascadeLake/Skylake).
	model           int64               // CPU model number (e.g. 85 for CascadeLake/Skylake).
	id              cpuID               // id for this thread
	bugs            map[string]struct{} // map of vulnerabilities parsed from the 'bugs' field.
}

// newThread parses a CPU from a single cpu entry from /proc/cpuinfo.
func newThread(data string) (*thread, error) {
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

	return &thread{
		processorNumber: processor,
		vendorID:        vendorID,
		cpuFamily:       cpuFamily,
		model:           model,
		id: cpuID{
			physicalID: physicalID,
			coreID:     coreID,
		},
		bugs: bugs,
	}, nil
}

// String implements the String method for thread.
func (t *thread) String() string {
	template := `CPU: %d
CPU ID: %+v
Vendor: %s
Family/Model: %d/%d
Bugs: %s
`
	bugs := make([]string, 0)
	for bug := range t.bugs {
		bugs = append(bugs, bug)
	}

	return fmt.Sprintf(template, t.processorNumber, t.id, t.vendorID, t.cpuFamily, t.model, strings.Join(bugs, ","))
}

// shutdown turns off the CPU by writing 0 to /sys/devices/cpu/cpu{N}/online.
func (t *thread) shutdown() error {
	cpuPath := fmt.Sprintf(cpuOnlineTemplate, t.processorNumber)
	return ioutil.WriteFile(cpuPath, []byte{'0'}, 0644)
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
func (t *thread) isVulnerable() bool {
	for _, bug := range vulnerabilities {
		if _, ok := t.bugs[bug]; ok {
			return true
		}
	}
	return false
}

// isActive checks if a CPU is active from /sys/devices/system/cpu/cpu{N}/online
// If the file does not exist (ioutil returns in error), we assume the CPU is on.
func (t *thread) isActive() bool {
	cpuPath := fmt.Sprintf(cpuOnlineTemplate, t.processorNumber)
	data, err := ioutil.ReadFile(cpuPath)
	if err != nil {
		return true
	}
	return len(data) > 0 && data[0] != '0'
}

// similarTo checks family/model/bugs fields for equality of two
// processors.
func (t *thread) similarTo(other *thread) bool {
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
