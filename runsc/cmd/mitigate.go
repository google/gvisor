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
	"os"
	"runtime"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/mitigate"
)

const (
	// cpuInfo is the path used to parse CPU info.
	cpuInfo = "/proc/cpuinfo"
	// Path to enable/disable SMT.
	smtPath = "/sys/devices/system/cpu/smt/control"
)

// Mitigate implements subcommands.Command for the "mitigate" command.
type Mitigate struct {
	// Run the command without changing the underlying system.
	dryRun bool
	// Reverse mitigate by turning on all CPU cores.
	reverse bool
	// Extra data for post mitigate operations.
	data string
	// Control to mitigate/reverse smt.
	control machineControl
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
func (m *Mitigate) Usage() string {
	return fmt.Sprintf(`mitigate [flags]

mitigate mitigates a system to the "MDS" vulnerability by writing "off" to %q. CPUs can be restored by writing "on" to the same file or rebooting your system.

The command can be reversed with --reverse, which writes "on" to the file above.%s`, smtPath, m.usage())
}

// SetFlags sets flags for the command Mitigate.
func (m *Mitigate) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&m.dryRun, "dryrun", false, "run the command without changing system")
	f.BoolVar(&m.reverse, "reverse", false, "reverse mitigate by enabling all CPUs")
	m.setFlags(f)
}

// Execute implements subcommands.Command.Execute.
func (m *Mitigate) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if runtime.GOARCH == "arm64" || runtime.GOARCH == "arm" {
		log.Warningf("As ARM is not affected by MDS, mitigate does not support ARM machines.")
		// Set reverse flag so that we still perform post mitigate operations. mitigate reverse is a noop in this case.
		m.reverse = true
	}

	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	m.control = &machineControlImpl{}
	return m.execute()
}

// execute executes mitigate operations. Seperate from Execute method for
// easier mocking.
func (m *Mitigate) execute() subcommands.ExitStatus {
	beforeSet, err := m.control.getCPUs()
	if err != nil {
		return Errorf("Get before CPUSet failed: %v", err)
	}
	log.Infof("CPUs before: %s", beforeSet.String())

	if err := m.doEnableDisable(beforeSet); err != nil {
		return Errorf("Enabled/Disable action failed on %q: %v", smtPath, err)
	}

	afterSet, err := m.control.getCPUs()
	if err != nil {
		return Errorf("Get after CPUSet failed: %v", err)
	}
	log.Infof("CPUs after: %s", afterSet.String())

	if err = m.postMitigate(afterSet); err != nil {
		return Errorf("Post Mitigate failed: %v", err)
	}

	return subcommands.ExitSuccess
}

// doEnableDisable does either enable or disable operation based on flags.
func (m *Mitigate) doEnableDisable(set mitigate.CPUSet) error {
	if m.reverse {
		if m.dryRun {
			log.Infof("Skipping reverse action because dryrun is set.")
			return nil
		}
		return m.control.enable()
	}
	if m.dryRun {
		log.Infof("Skipping mitigate action because dryrun is set.")
		return nil
	}
	if set.IsVulnerable() {
		return m.control.disable()
	}
	log.Infof("CPUs not vulnerable. Skipping disable call.")
	return nil
}

// Interface to wrap interactions with underlying machine. Done
// so testing with mocks can be done hermetically.
type machineControl interface {
	enable() error
	disable() error
	isEnabled() (bool, error)
	getCPUs() (mitigate.CPUSet, error)
}

// Implementation of SMT control interaction with the underlying machine.
type machineControlImpl struct{}

func (*machineControlImpl) enable() error {
	return checkFileExistsOnWrite("enable", "on")
}

func (*machineControlImpl) disable() error {
	return checkFileExistsOnWrite("disable", "off")
}

// Writes data to SMT control. If file not found, logs file not exist error and returns nil
// error, which is done because machines without the file pointed to by smtPath only have one
// thread per core in the first place. Otherwise returns error from ioutil.WriteFile.
func checkFileExistsOnWrite(op, data string) error {
	err := ioutil.WriteFile(smtPath, []byte(data), 0644)
	if err != nil && os.IsExist(err) {
		log.Infof("File %q does not exist for operation %s. This machine probably has no smt control.", smtPath, op)
		return nil
	}
	return err
}

func (*machineControlImpl) isEnabled() (bool, error) {
	data, err := ioutil.ReadFile(cpuInfo)
	return string(data) == "on", err
}

func (*machineControlImpl) getCPUs() (mitigate.CPUSet, error) {
	data, err := ioutil.ReadFile(cpuInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", cpuInfo, err)
	}
	set, err := mitigate.NewCPUSet(string(data))
	if err != nil {
		return nil, fmt.Errorf("getCPUs: %v", err)
	}
	return set, nil
}
