// Copyright 2022 The gVisor Authors.
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

package linux

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unicode"

	"gvisor.dev/gvisor/pkg/sentry/seccheck"
)

func findPoint(name string) (seccheck.PointDesc, bool) {
	for _, pt := range seccheck.Points {
		if pt.Name == name {
			return pt, true
		}
	}
	return seccheck.PointDesc{}, false
}

// TestSeccheckMax catches cases that a new syscall was added but seccheck raw
// syscall numbers (e.g. syscall/sysno/123) have not been updated.
func TestSeccheckMax(t *testing.T) {
	max := uintptr(0)
	for sysno := range archToTest.Table {
		if sysno > max {
			max = sysno
		}
	}

	want := fmt.Sprintf("syscall/sysno/%d/enter", max)
	if _, ok := findPoint(want); !ok {
		t.Errorf("seccheck.PointDesc for syscall %d not found. Update pkg/sentry/seccheck/metadata_amd64.go", max)
	}
}

// TestSeccheckSyscalls verifies that all syscalls registered with a point
// callback have the corresponding seccheck metadata created.
func TestSeccheckSyscalls(t *testing.T) {
	for sysno, syscall := range archToTest.Table {
		if syscall.PointCallback == nil {
			continue
		}

		// For every syscall with a PointCallback, there must be a corresponding
		// seccheck.PointDesc created.
		funcName := runtime.FuncForPC(reflect.ValueOf(syscall.PointCallback).Pointer()).Name()
		if idx := strings.LastIndex(funcName, "."); idx > -1 {
			funcName = funcName[idx+1:]
		}
		t.Run(funcName, func(t *testing.T) {
			if !strings.HasPrefix(funcName, "Point") {
				t.Errorf("PointCallback function name must start with Point: %q", funcName)
			}
			funcName = strings.TrimPrefix(funcName, "Point")
			if len(funcName) == 0 {
				t.Errorf("PointCallback function name invalid: %q", funcName)
			}

			pointName := strings.ToLower(string(funcName[0]))
			for _, c := range funcName[1:] {
				if unicode.IsUpper(c) {
					pointName += "_"
				}
				pointName += string(unicode.ToLower(c))
			}

			for _, flavor := range []struct {
				suffix string
				typ    seccheck.SyscallType
			}{
				{suffix: "enter", typ: seccheck.SyscallEnter},
				{suffix: "exit", typ: seccheck.SyscallExit},
			} {
				fullName := fmt.Sprintf("syscall/%s/%s", pointName, flavor.suffix)
				pt, ok := findPoint(fullName)
				if !ok {
					t.Fatalf("seccheck.PointDesc %q not found.", fullName)
				}
				if want := seccheck.GetPointForSyscall(flavor.typ, sysno); want != pt.ID {
					t.Errorf("seccheck.Point for syscall %q is wrong, want: %v, got: %v", pointName, want, pt.ID)
				}
			}
		})
	}
}
