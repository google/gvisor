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

package cmd

import (
	"context"
	"fmt"
	"io/ioutil"
	"runtime"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/mitigate"
)

const (
	// cpuInfo is the path used to parse CPU info.
	cpuInfo = "/proc/cpuinfo"
	// allPossibleCPUs is the path used to enable CPUs.
	allPossibleCPUs = "/sys/devices/system/cpu/possible"
)

// Mitigate implements subcommands.Command for the "mitigate" command.
type Mitigate struct {
	// Run the command without changing the underlying system.
	dryRun bool
	// Reverse mitigate by turning on all CPU cores.
	reverse bool
	// Path to file to read to create CPUSet.
	path string
	// Callback to check if a given thread is vulnerable.
	vulnerable func(other mitigate.Thread) bool
}

// Name implements subcommands.command.name.
func (*Mitigate) Name() string {
	return "mitigate"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Mitigate) Synopsis() string {
	return "mitigate mitigates the underlying system against side channel attacks"
}

// Usage implments Usage for cmd.Mitigate.
func (m Mitigate) Usage() string {
	return `mitigate [flags]

mitigate mitigates a system to the "MDS" vulnerability by implementing a manual shutdown of SMT. The command checks /proc/cpuinfo for cpus having the MDS vulnerability, and if found, shutdown all but one CPU per hyperthread pair via /sys/devices/system/cpu/cpu{N}/online. CPUs can be restored by writing "2" to each file in /sys/devices/system/cpu/cpu{N}/online or performing a system reboot.

The command can be reversed with --reverse, which reads the total CPUs from /sys/devices/system/cpu/possible and enables all with /sys/devices/system/cpu/cpu{N}/online.`
}

// SetFlags sets flags for the command Mitigate.
func (m *Mitigate) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&m.dryRun, "dryrun", false, "run the command without changing system")
	f.BoolVar(&m.reverse, "reverse", false, "reverse mitigate by enabling all CPUs")
}

// Execute implements subcommands.Command.Execute.
func (m *Mitigate) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if runtime.GOARCH == "arm64" || runtime.GOARCH == "arm" {
		log.Warningf("As ARM is not affected by MDS, mitigate does not support")
		return subcommands.ExitFailure
	}

	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	m.path = cpuInfo
	if m.reverse {
		m.path = allPossibleCPUs
	}

	m.vulnerable = func(other mitigate.Thread) bool {
		return other.IsVulnerable()
	}

	if _, err := m.doExecute(); err != nil {
		log.Warningf("Execute failed: %v", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

// Execute executes the Mitigate command.
func (m *Mitigate) doExecute() (mitigate.CPUSet, error) {
	if m.dryRun {
		log.Infof("Running with DryRun. No cpu settings will be changed.")
	}
	if m.reverse {
		data, err := ioutil.ReadFile(m.path)
		if err != nil {
			return nil, fmt.Errorf("failed to read %s: %v", m.path, err)
		}

		set, err := m.doReverse(data)
		if err != nil {
			return nil, fmt.Errorf("reverse operation failed: %v", err)
		}
		return set, nil
	}

	data, err := ioutil.ReadFile(m.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", m.path, err)
	}
	set, err := m.doMitigate(data)
	if err != nil {
		return nil, fmt.Errorf("mitigate operation failed: %v", err)
	}
	return set, nil
}

func (m *Mitigate) doMitigate(data []byte) (mitigate.CPUSet, error) {
	set, err := mitigate.NewCPUSet(data, m.vulnerable)
	if err != nil {
		return nil, err
	}

	log.Infof("Mitigate found the following CPUs...")
	log.Infof("%s", set)

	disableList := set.GetShutdownList()
	log.Infof("Disabling threads on thread pairs.")
	for _, t := range disableList {
		log.Infof("Disable thread: %s", t)
		if m.dryRun {
			continue
		}
		if err := t.Disable(); err != nil {
			return nil, fmt.Errorf("error disabling thread: %s err: %v", t, err)
		}
	}
	log.Infof("Shutdown successful.")
	return set, nil
}

func (m *Mitigate) doReverse(data []byte) (mitigate.CPUSet, error) {
	set, err := mitigate.NewCPUSetFromPossible(data)
	if err != nil {
		return nil, err
	}

	log.Infof("Reverse mitigate found the following CPUs...")
	log.Infof("%s", set)

	enableList := set.GetRemainingList()

	log.Infof("Enabling all CPUs...")
	for _, t := range enableList {
		log.Infof("Enabling thread: %s", t)
		if m.dryRun {
			continue
		}
		if err := t.Enable(); err != nil {
			return nil, fmt.Errorf("error enabling thread: %s err: %v", t, err)
		}
	}
	log.Infof("Enable successful.")
	return set, nil
}
