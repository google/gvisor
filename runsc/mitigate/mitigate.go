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
	"io/ioutil"
	"os"
	"regexp"
	"sort"
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

	// Path to shutdown a CPU.
	cpuOnlineTemplate = "/sys/devices/system/cpu/cpu%d/online"
)

// CPUSet contains a map of all CPUs on the system, mapped
// by Physical ID and CoreIDs. threads with the same
// Core and Physical ID are Hyperthread pairs.
type CPUSet map[threadID]*ThreadGroup

// NewCPUSet creates a CPUSet from data read from /proc/cpuinfo.
func NewCPUSet(data []byte) (CPUSet, error) {
	processors, err := getThreads(string(data))
	if err != nil {
		return nil, err
	}

	set := make(CPUSet)
	for _, p := range processors {
		// Each ID is of the form physicalID:coreID. Hyperthread pairs
		// have identical physical and core IDs. We need to match
		// Hyperthread pairs so that we can shutdown all but one per
		// pair.
		core, ok := set[p.id]
		if !ok {
			core = &ThreadGroup{}
			set[p.id] = core
		}
		core.isVulnerable = core.isVulnerable || p.IsVulnerable()
		core.threads = append(core.threads, p)
	}

	// We need to make sure we shutdown the lowest number processor per
	// thread group.
	for _, tg := range set {
		sort.Slice(tg.threads, func(i, j int) bool {
			return tg.threads[i].processorNumber < tg.threads[j].processorNumber
		})
	}
	return set, nil
}

// NewCPUSetFromPossible makes a cpuSet data read from
// /sys/devices/system/cpu/possible. This is used in enable operations
// where the caller simply wants to enable all CPUS.
func NewCPUSetFromPossible(data []byte) (CPUSet, error) {
	threads, err := GetThreadsFromPossible(data)
	if err != nil {
		return nil, err
	}

	// We don't care if a CPU is vulnerable or not, we just
	// want to return a list of all CPUs on the host.
	set := CPUSet{
		threads[0].id: &ThreadGroup{
			threads:      threads,
			isVulnerable: false,
		},
	}
	return set, nil
}

// String implements the String method for CPUSet.
func (c CPUSet) String() string {
	ret := ""
	for _, tg := range c {
		ret += fmt.Sprintf("%s\n", tg)
	}
	return ret
}

// GetRemainingList returns the list of threads that will remain active
// after mitigation.
func (c CPUSet) GetRemainingList() []Thread {
	threads := make([]Thread, 0, len(c))
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

// GetShutdownList returns the list of threads that will be shutdown on
// mitigation.
func (c CPUSet) GetShutdownList() []Thread {
	threads := make([]Thread, 0)
	for _, core := range c {
		// Only if we're vulnerable do shutdown anything. In this case,
		// shutdown all but the first entry.
		if core.isVulnerable && len(core.threads) > 1 {
			threads = append(threads, core.threads[1:]...)
		}
	}
	return threads
}

// ThreadGroup represents Hyperthread pairs on the same physical/core ID.
type ThreadGroup struct {
	threads      []Thread
	isVulnerable bool
}

// String implements the String method for threadGroup.
func (c ThreadGroup) String() string {
	ret := fmt.Sprintf("ThreadGroup:\nIsVulnerable: %t\n", c.isVulnerable)
	for _, processor := range c.threads {
		ret += fmt.Sprintf("%s\n", processor)
	}
	return ret
}

// getThreads returns threads structs from reading /proc/cpuinfo.
func getThreads(data string) ([]Thread, error) {
	// Each processor entry should start with the
	// processor key. Find the beginings of each.
	r := buildRegex(processorKey, `\d+`)
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
	cpus := make([]Thread, 0, len(indices))
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

// GetThreadsFromPossible makes threads from data read from /sys/devices/system/cpu/possible.
func GetThreadsFromPossible(data []byte) ([]Thread, error) {
	possibleRegex := regexp.MustCompile(`(?m)^(\d+)(-(\d+))?$`)
	matches := possibleRegex.FindStringSubmatch(string(data))
	if len(matches) != 4 {
		return nil, fmt.Errorf("mismatch regex from possible: %q", string(data))
	}

	// If matches[3] is empty, we only have one cpu entry.
	if matches[3] == "" {
		matches[3] = matches[1]
	}

	begin, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse begin: %v", err)
	}
	end, err := strconv.ParseInt(matches[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse end: %v", err)
	}
	if begin > end || begin < 0 || end < 0 {
		return nil, fmt.Errorf("invalid cpu bounds from possible: begin: %d end: %d", begin, end)
	}

	ret := make([]Thread, 0, end-begin)
	for i := begin; i <= end; i++ {
		ret = append(ret, Thread{
			processorNumber: i,
			id: threadID{
				physicalID: 0, // we don't care about id for enable ops.
				coreID:     0,
			},
		})
	}

	return ret, nil
}

// threadID for each thread is defined by the physical and
// core IDs. If equal, two threads are Hyperthread pairs.
type threadID struct {
	physicalID int64
	coreID     int64
}

// Thread represents pertinent info about a single hyperthread in a pair.
type Thread struct {
	processorNumber int64               // the processor number of this CPU.
	vendorID        string              // the vendorID of CPU (e.g. AuthenticAMD).
	cpuFamily       int64               // CPU family number (e.g. 6 for CascadeLake/Skylake).
	model           int64               // CPU model number (e.g. 85 for CascadeLake/Skylake).
	id              threadID            // id for this thread
	bugs            map[string]struct{} // map of vulnerabilities parsed from the 'bugs' field.
}

// newThread parses a CPU from a single cpu entry from /proc/cpuinfo.
func newThread(data string) (Thread, error) {
	empty := Thread{}
	processor, err := parseProcessor(data)
	if err != nil {
		return empty, err
	}

	vendorID, err := parseVendorID(data)
	if err != nil {
		return empty, err
	}

	cpuFamily, err := parseCPUFamily(data)
	if err != nil {
		return empty, err
	}

	model, err := parseModel(data)
	if err != nil {
		return empty, err
	}

	physicalID, err := parsePhysicalID(data)
	if err != nil {
		return empty, err
	}

	coreID, err := parseCoreID(data)
	if err != nil {
		return empty, err
	}

	bugs, err := parseBugs(data)
	if err != nil {
		return empty, err
	}

	return Thread{
		processorNumber: processor,
		vendorID:        vendorID,
		cpuFamily:       cpuFamily,
		model:           model,
		id: threadID{
			physicalID: physicalID,
			coreID:     coreID,
		},
		bugs: bugs,
	}, nil
}

// String implements the String method for thread.
func (t Thread) String() string {
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

// Enable turns on the CPU by writing 1 to /sys/devices/cpu/cpu{N}/online.
func (t Thread) Enable() error {
	// Linux ensures that "cpu0" is always online.
	if t.processorNumber == 0 {
		return nil
	}
	cpuPath := fmt.Sprintf(cpuOnlineTemplate, t.processorNumber)
	f, err := os.OpenFile(cpuPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", cpuPath, err)
	}
	if _, err = f.Write([]byte{'1'}); err != nil {
		return fmt.Errorf("failed to write '1' to %s: %v", cpuPath, err)
	}
	return nil
}

// Disable turns off the CPU by writing 0 to /sys/devices/cpu/cpu{N}/online.
func (t Thread) Disable() error {
	// The core labeled "cpu0" can never be taken offline via this method.
	// Linux will return EPERM if the user even creates a file at the /sys
	// path above.
	if t.processorNumber == 0 {
		return fmt.Errorf("invalid shutdown operation: cpu0 cannot be disabled")
	}
	cpuPath := fmt.Sprintf(cpuOnlineTemplate, t.processorNumber)
	return ioutil.WriteFile(cpuPath, []byte{'0'}, 0644)
}

// IsVulnerable checks if a CPU is vulnerable to mds.
func (t Thread) IsVulnerable() bool {
	_, ok := t.bugs[mds]
	return ok
}

// isActive checks if a CPU is active from /sys/devices/system/cpu/cpu{N}/online
// If the file does not exist (ioutil returns in error), we assume the CPU is on.
func (t Thread) isActive() bool {
	cpuPath := fmt.Sprintf(cpuOnlineTemplate, t.processorNumber)
	data, err := ioutil.ReadFile(cpuPath)
	if err != nil {
		return true
	}
	return len(data) > 0 && data[0] != '0'
}

// SimilarTo checks family/model/bugs fields for equality of two
// processors.
func (t Thread) SimilarTo(other Thread) bool {
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
		return "", fmt.Errorf("failed to match key %q: %q", key, data)
	}
	return matches[1], nil
}
