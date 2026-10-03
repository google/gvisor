// Copyright 2026 The gVisor Authors.
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

package checkescape

import (
	"strings"
	"testing"
)

// Entry-point contracts must not suppress calls to an interior offset or an
// unfamiliar operand, and relocation parsing must preserve package names.
func TestCallTargetIdentity(t *testing.T) {
	for _, test := range []struct {
		name        string
		instruction string
		target      callTarget
		allocation  bool
	}{
		{"entry", "CALL 0(PC) [0:4]R_CALLARM64:runtime.gcWriteBarrier2<1>", callTarget{name: "runtime.gcWriteBarrier2", kind: symbolTarget}, false},
		{"positive_offset", "CALL 0(PC) [0:4]R_CALLARM64:runtime.gcWriteBarrier2<1>+8", callTarget{name: "runtime.gcWriteBarrier2", offset: 8, kind: symbolTarget}, true},
		{"negative_offset", "CALL 0x1234 [1:5]R_CALL:runtime.gcWriteBarrier2<1>+-8", callTarget{name: "runtime.gcWriteBarrier2", offset: -8, kind: symbolTarget}, true},
		{"malformed_offset", "CALL 0x1234 [1:5]R_CALL:runtime.gcWriteBarrier2+invalid", callTarget{name: "0x1234"}, true},
		{"package_hyphen", "CALL 0x1234 [1:5]R_CALL:example.com/some-package.Func", callTarget{name: "example.com/some-package.Func", kind: symbolTarget}, false},
		{"numeric", "CALL 0x1234", callTarget{name: "0x1234"}, true},
		{"memory", "CALL 8(AX)", callTarget{name: "8(AX)"}, true},
		{"symbolized_memory", "CALL runtime.gcWriteBarrier2(SB)", callTarget{name: "runtime.gcWriteBarrier2(SB)"}, true},
		{"retpoline_entry", "CALL 0x1234 [1:5]R_CALL:runtime.retpolineDX", callTarget{name: "runtime.retpolineDX", kind: indirectTarget}, false},
		{"retpoline_offset", "CALL 0x1234 [1:5]R_CALL:runtime.retpolineDX+8", callTarget{name: "runtime.retpolineDX", offset: 8, kind: symbolTarget}, true},
		{"unnamed_entry", "CALL 0x1234 [1:5]R_CALL", callTarget{name: "0x1234", kind: unnamedTarget}, false},
		{"unnamed_entry_arm64", "CALL 0(PC) [0:4]R_CALLARM64", callTarget{name: "0(PC)", kind: unnamedTarget}, false},
		{"unnamed_offset", "CALL 0x1234 [1:5]R_CALL:8", callTarget{name: "0x1234", offset: 8, kind: unnamedTarget}, true},
		{"unnamed_negative_offset", "CALL 0(PC) [0:4]R_CALLARM64:-8", callTarget{name: "0(PC)", offset: -8, kind: unnamedTarget}, true},
		{"other_relocation", "CALL 0x1234 [1:5]R_CALLIND", callTarget{name: "0x1234"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := parseCallTarget(strings.Fields("source.go:1 0x100 00000000 " + test.instruction))
			if target != test.target {
				t.Fatalf("target = %#v, want %#v", target, test.target)
			}
			calls := callSet{target: {}}
			if got := len(calls.forKind(allocationCall)) != 0; got != test.allocation {
				t.Errorf("allocation evidence = %t, want %t", got, test.allocation)
			}
			if test.target.kind == indirectTarget || test.target.kind == unnamedTarget {
				for _, kind := range []callKind{anyCall, implicitCall} {
					if len(calls.forKind(kind)) == 0 {
						t.Errorf("target kind %d lost its evidence for kind %d", test.target.kind, kind)
					}
				}
			}
		})
	}
}
