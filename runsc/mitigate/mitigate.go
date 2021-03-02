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
// shuts down CPUs via /sys/devices/system/cpu/cpu{N}/online. In addition,
// the mitigate also handles computing available CPU in kubernetes kube_config
// files.
package mitigate

import (
	"fmt"
	"io/ioutil"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
)

const (
	cpuInfo         = "/proc/cpuinfo"
	allPossibleCPUs = "/sys/devices/system/cpu/possible"
)

// Mitigate handles high level mitigate operations provided to runsc.
type Mitigate struct {
	dryRun  bool     // Run the command without changing the underlying system.
	reverse bool     // Reverse mitigate by turning on all CPU cores.
	other   mitigate // Struct holds extra mitigate logic.
	path    string   // path to read for each operation (e.g. /proc/cpuinfo).
}

// Usage implments Usage for cmd.Mitigate.
func (m Mitigate) Usage() string {
	usageString := `mitigate [flags]

Mitigate mitigates a system to the "MDS" vulnerability by implementing a manual shutdown of SMT. The command checks /proc/cpuinfo for cpus having the MDS vulnerability, and if found, shutdown all but one CPU per hyperthread pair via /sys/devices/system/cpu/cpu{N}/online. CPUs can be restored by writing "2" to each file in /sys/devices/system/cpu/cpu{N}/online or performing a system reboot.

The command can be reversed with --reverse, which reads the total CPUs from /sys/devices/system/cpu/possible and enables all with /sys/devices/system/cpu/cpu{N}/online.
`
	return usageString + m.other.usage()
}

// SetFlags sets flags for the command Mitigate.
func (m Mitigate) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&m.dryRun, "dryrun", false, "run the command without changing system")
	f.BoolVar(&m.reverse, "reverse", false, "reverse mitigate by enabling all CPUs")
	m.other.setFlags(f)
	m.path = cpuInfo
	if m.reverse {
		m.path = allPossibleCPUs
	}
}

// Execute executes the Mitigate command.
func (m Mitigate) Execute() error {
	data, err := ioutil.ReadFile(m.path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", m.path, err)
	}

	if m.reverse {
		err := m.doReverse(data)
		if err != nil {
			return fmt.Errorf("reverse operation failed: %v", err)
		}
		return nil
	}

	set, err := m.doMitigate(data)
	if err != nil {
		return fmt.Errorf("mitigate operation failed: %v", err)
	}
	return m.other.execute(set, m.dryRun)
}

func (m Mitigate) doMitigate(data []byte) (cpuSet, error) {
	set, err := newCPUSet(data, m.other.vulnerable)
	if err != nil {
		return nil, err
	}

	log.Infof("Mitigate found the following CPUs...")
	log.Infof("%s", set)

	disableList := set.getShutdownList()
	log.Infof("Disabling threads on thread pairs.")
	for _, t := range disableList {
		log.Infof("Disable thread: %s", t)
		if m.dryRun {
			continue
		}
		if err := t.disable(); err != nil {
			return nil, fmt.Errorf("error disabling thread: %s err: %v", t, err)
		}
	}
	log.Infof("Shutdown successful.")
	return set, nil
}

func (m Mitigate) doReverse(data []byte) error {
	set, err := newCPUSetFromPossible(data)
	if err != nil {
		return err
	}

	log.Infof("Reverse mitigate found the following CPUs...")
	log.Infof("%s", set)

	enableList := set.getRemainingList()

	log.Infof("Enabling all CPUs...")
	for _, t := range enableList {
		log.Infof("Enabling thread: %s", t)
		if m.dryRun {
			continue
		}
		if err := t.enable(); err != nil {
			return fmt.Errorf("error enabling thread: %s err: %v", t, err)
		}
	}
	log.Infof("Enable successful.")
	return nil
}
