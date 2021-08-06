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

//go:build amd64
// +build amd64

package cmd

import (
	"testing"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/mitigate"
)

type mockMachineControl struct {
	enabled bool
	cpus    mitigate.CPUSet
}

func (m *mockMachineControl) enable() error {
	m.enabled = true
	return nil
}

func (m *mockMachineControl) disable() error {
	if m.cpus.IsVulnerable() {
		m.enabled = false
	}
	return nil
}

func (m *mockMachineControl) isEnabled() (bool, error) {
	return m.enabled, nil
}

func (m *mockMachineControl) getCPUs() (mitigate.CPUSet, error) {
	set := m.cpus
	if !m.enabled {
		set = m.cpus[:len(m.cpus)/2]
	}

	// Instead of just returning the created CPU set stored in this struct, call
	// NewCPUSet to exercise that code path as the machineControlImpl would.
	return mitigate.NewCPUSet(set.String())
}

type executeTestCase struct {
	name                string
	cpu                 mitigate.MockCPU
	mitigateWantCPUs    int
	mitigateError       subcommands.ExitStatus
	mitigateWantEnabled bool
	reverseWantCPUs     int
	reverseError        subcommands.ExitStatus
	reverseWantEnabled  bool
	dryrun              bool
}

func TestExecute(t *testing.T) {
	for _, tc := range []executeTestCase{
		{
			name:                "CascadeLake4",
			cpu:                 mitigate.CascadeLake4,
			mitigateWantCPUs:    2,
			mitigateWantEnabled: false,
			reverseWantCPUs:     4,
			reverseWantEnabled:  true,
		},
		{
			name:                "CascadeLake4DryRun",
			cpu:                 mitigate.CascadeLake4,
			mitigateWantCPUs:    4,
			mitigateWantEnabled: true,
			reverseWantCPUs:     4,
			reverseWantEnabled:  true,
			dryrun:              true,
		},
		{
			name:                "AMD8",
			cpu:                 mitigate.AMD8,
			mitigateWantCPUs:    8,
			mitigateWantEnabled: true,
			reverseWantCPUs:     8,
			reverseWantEnabled:  true,
		},
		{
			name:          "Empty",
			cpu:           mitigate.Empty,
			mitigateError: Errorf(`mitigate operation failed: no cpus found for: ""`),
			reverseError:  Errorf(`mitigate operation failed: no cpus found for: ""`),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := tc.cpu.MakeCPUSet()
			m := &Mitigate{
				control: &mockMachineControl{
					enabled: true,
					cpus:    set,
				},
				dryRun: tc.dryrun,
			}
			t.Run("Mitigate", func(t *testing.T) {
				m.doExecuteTest(t, tc.mitigateWantEnabled, tc.mitigateWantCPUs, tc.mitigateError)
			})

			m.reverse = true
			t.Run("Reverse", func(t *testing.T) {
				m.doExecuteTest(t, tc.reverseWantEnabled, tc.reverseWantCPUs, tc.reverseError)
			})
		})
	}
}

// doExecuteTest runs Execute with the mitigate operation and reverse operation.
func (m *Mitigate) doExecuteTest(t *testing.T, wantEnabled bool, wantCPUs int, wantErr subcommands.ExitStatus) {
	subError := m.execute()
	if subError != wantErr {
		t.Fatalf("Mitigate error mismatch: want: %v got: %v", wantErr, subError)
	}

	// case where test should end in error or we don't care
	// about how many cpus are returned.
	if wantErr != subcommands.ExitSuccess {
		log.Infof("return")
		return
	}

	gotEnabled, _ := m.control.isEnabled()
	if wantEnabled != gotEnabled {
		t.Fatalf("Incorrect enabled state: want: %t got: %t", wantEnabled, gotEnabled)
	}

	gotCPUs, _ := m.control.getCPUs()
	if len(gotCPUs) != wantCPUs {
		t.Fatalf("Incorrect number of CPUs: want: %d got: %d", wantCPUs, len(gotCPUs))
	}
}
