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

// +build amd64

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/runsc/mitigate/mock"
)

type executeTestCase struct {
	name          string
	mitigateData  string
	mitigateError error
	mitigateCPU   int
	reverseData   string
	reverseError  error
	reverseCPU    int
}

func TestExecute(t *testing.T) {

	partial := `processor       : 1
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 49
model name      : AMD EPYC 7B12
physical id     : 0
bugs         : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
power management:
`

	for _, tc := range []executeTestCase{
		{
			name:         "CascadeLake4",
			mitigateData: mock.CascadeLake4.MakeCPUString(),
			mitigateCPU:  2,
			reverseData:  mock.CascadeLake4.MakeSysPossibleString(),
			reverseCPU:   4,
		},
		{
			name:          "Empty",
			mitigateData:  "",
			mitigateError: fmt.Errorf(`mitigate operation failed: no cpus found for: ""`),
			reverseData:   "",
			reverseError:  fmt.Errorf(`reverse operation failed: mismatch regex from possible: ""`),
		},
		{
			name: "Partial",
			mitigateData: `processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 49
model name      : AMD EPYC 7B12
physical id     : 0
core id         : 0
cpu cores       : 1
bugs            : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
power management::84

` + partial,
			mitigateError: fmt.Errorf(`mitigate operation failed: failed to match key "core id": %q`, partial),
			reverseData:   "1-",
			reverseError:  fmt.Errorf(`reverse operation failed: mismatch regex from possible: %q`, "1-"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &Mitigate{
				dryRun: true,
			}
			m.doExecuteTest(t, "Mitigate", tc.mitigateData, tc.mitigateCPU, tc.mitigateError)

			m.reverse = true
			m.doExecuteTest(t, "Reverse", tc.reverseData, tc.reverseCPU, tc.reverseError)
		})
	}
}

func TestExecuteSmoke(t *testing.T) {
	smokeMitigate, err := ioutil.ReadFile(cpuInfo)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", cpuInfo, err)
	}

	m := &Mitigate{
		dryRun: true,
	}

	m.doExecuteTest(t, "Mitigate", string(smokeMitigate), 0, nil)

	smokeReverse, err := ioutil.ReadFile(allPossibleCPUs)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", allPossibleCPUs, err)
	}

	m.reverse = true
	m.doExecuteTest(t, "Reverse", string(smokeReverse), 0, nil)
}

// doExecuteTest runs Execute with the mitigate operation and reverse operation.
func (m *Mitigate) doExecuteTest(t *testing.T, name, data string, want int, wantErr error) {
	t.Run(name, func(t *testing.T) {
		file, err := ioutil.TempFile("", "outfile.txt")
		if err != nil {
			t.Fatalf("Failed to create tmpfile: %v", err)
		}
		defer os.Remove(file.Name())

		if _, err := file.WriteString(data); err != nil {
			t.Fatalf("Failed to write to file: %v", err)
		}

		// Set fields for mitigate and dryrun to keep test hermetic.
		m.path = file.Name()

		set, err := m.doExecute()
		if err = checkErr(wantErr, err); err != nil {
			t.Fatalf("Mitigate error mismatch: %v", err)
		}

		// case where test should end in error or we don't care
		// about how many cpus are returned.
		if wantErr != nil || want < 1 {
			return
		}
		got := len(set.GetRemainingList())
		if want != got {
			t.Fatalf("Failed wrong number of remaining CPUs: want %d, got %d", want, got)
		}

	})
}

// checkErr checks error for equality.
func checkErr(want, got error) error {
	switch {
	case want == nil && got == nil:
	case want != nil && got == nil:
		fallthrough
	case want == nil && got != nil:
		fallthrough
	case want.Error() != strings.Trim(got.Error(), " "):
		return fmt.Errorf("got: %v want: %v", got, want)
	}
	return nil
}
