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
	// Extra data for post mitigate operations.
	data string
}

// Name implements subcommands.command.name.
func (*Mitigate) Name() string {
	return "mitigate"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Mitigate) Synopsis() string {
	return "mitigate mitigates the underlying system against side channel attacks"
}

// Usage implements Usage for cmd.Mitigate.
func (m Mitigate) Usage() string {
	return fmt.Sprintf(`mitigate [flags]

mitigate mitigates a system to the "MDS" vulnerability by implementing a manual shutdown of SMT. The command checks /proc/cpuinfo for cpus having the MDS vulnerability, and if found, shutdown all but one CPU per hyperthread pair via /sys/devices/system/cpu/cpu{N}/online. CPUs can be restored by writing "2" to each file in /sys/devices/system/cpu/cpu{N}/online or performing a system reboot.

The command can be reversed with --reverse, which reads the total CPUs from /sys/devices/system/cpu/possible and enables all with /sys/devices/system/cpu/cpu{N}/online.%s`, m.usage())
}

// SetFlags sets flags for the command Mitigate.
func (m *Mitigate) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&m.dryRun, "dryrun", false, "run the command without changing system")
	f.BoolVar(&m.reverse, "reverse", false, "reverse mitigate by enabling all CPUs")
	m.setFlags(f)
}

// Execute implements subcommands.Command.Execute.
func (m *Mitigate) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	m.path = cpuInfo
	if m.reverse {
		m.path = allPossibleCPUs
	}

	set, err := m.doExecute()
	if err != nil {
		return Errorf("Execute failed: %v", err)
	}

	if m.data == "" {
		return subcommands.ExitSuccess
	}

	if err = m.postMitigate(set); err != nil {
		return Errorf("Post Mitigate failed: %v", err)
	}

	return subcommands.ExitSuccess
}

// Execute executes the Mitigate command.
func (m *Mitigate) doExecute() (mitigate.CPUSet, error) {
	if m.dryRun {
		log.Infof("Running with DryRun. No cpu settings will be changed.")
	}
	data, err := ioutil.ReadFile(m.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", m.path, err)
	}
	if m.reverse {
		set, err := m.doReverse(data)
		if err != nil {
			return nil, fmt.Errorf("reverse operation failed: %w", err)
		}
		return set, nil
	}
	set, err := m.doMitigate(data)
	if err != nil {
		return nil, fmt.Errorf("mitigate operation failed: %w", err)
	}
	return set, nil
}

func (m *Mitigate) doMitigate(data []byte) (mitigate.CPUSet, error) {
	set, err := mitigate.NewCPUSet(data)
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
			return nil, fmt.Errorf("error disabling thread: %s err: %w", t, err)
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
			return nil, fmt.Errorf("error enabling thread: %s err: %w", t, err)
		}
	}
	log.Infof("Enable successful.")
	return set, nil
}
