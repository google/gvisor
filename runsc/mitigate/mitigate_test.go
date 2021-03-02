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
	"os"
	"strings"
	"testing"
)

type executeTestCase struct {
	name          string
	mitigateData  string
	mitigateError error
	reverseData   string
	reverseError  error
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
			mitigateData: cascadeLake4.makeCPUString(),
			reverseData:  cascadeLake4.makeSysPossibleString(),
		},
		{
			name:          "Empty",
			mitigateData:  "",
			mitigateError: fmt.Errorf(`mitigate operation failed: no cpus found for: ""`),
			reverseData:   "",
			reverseError:  fmt.Errorf(`reverse operation failed: mismatch regex from %s: ""`, allPossibleCPUs),
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
power management:

` + partial,
			mitigateError: fmt.Errorf(`mitigate operation failed: failed to match key "core id": %q`, partial),
			reverseData:   "1-",
			reverseError:  fmt.Errorf(`reverse operation failed: mismatch regex from %s: %q`, allPossibleCPUs, "1-"),
		},
	} {
		doExecuteTest(t, Mitigate{}, tc)
	}
}

func TestExecuteSmoke(t *testing.T) {
	smokeMitigate, err := ioutil.ReadFile(cpuInfo)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", cpuInfo, err)
	}
	smokeReverse, err := ioutil.ReadFile(allPossibleCPUs)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", allPossibleCPUs, err)
	}
	doExecuteTest(t, Mitigate{}, executeTestCase{
		name:         "SmokeTest",
		mitigateData: string(smokeMitigate),
		reverseData:  string(smokeReverse),
	})

}

// doExecuteTest runs Execute with the mitigate operation and reverse operation.
func doExecuteTest(t *testing.T, m Mitigate, tc executeTestCase) {
	t.Run("Mitigate"+tc.name, func(t *testing.T) {
		m.dryRun = true
		file, err := ioutil.TempFile("", "outfile.txt")
		if err != nil {
			t.Fatalf("Failed to create tmpfile: %v", err)
		}
		defer os.Remove(file.Name())

		if _, err := file.WriteString(tc.mitigateData); err != nil {
			t.Fatalf("Failed to write to file: %v", err)
		}

		m.path = file.Name()

		got := m.Execute()
		if err = checkErr(tc.mitigateError, got); err != nil {
			t.Fatalf("Mitigate error mismatch: %v", err)
		}
	})
	t.Run("Reverse"+tc.name, func(t *testing.T) {
		m.dryRun = true
		m.reverse = true

		file, err := ioutil.TempFile("", "outfile.txt")
		if err != nil {
			t.Fatalf("Failed to create tmpfile: %v", err)
		}
		defer os.Remove(file.Name())

		if _, err := file.WriteString(tc.reverseData); err != nil {
			t.Fatalf("Failed to write to file: %v", err)
		}

		m.path = file.Name()
		got := m.Execute()
		if err = checkErr(tc.reverseError, got); err != nil {
			t.Fatalf("Mitigate error mismatch: %v", err)
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
