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

package systrap

import (
	"math/rand/v2"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/stubfilter"
)

// TestStubFilterPrecompiled checks that rendering the precompiled stub
// programs yields the same bytecode as compiling them with the same values,
// for randomized stub addresses as chosen by stubInit.
func TestStubFilterPrecompiled(t *testing.T) {
	const stubROMapLen = 0x9000
	rendered := map[string][]bpf.Instruction{}
	for range 16 {
		stubStart := rand.Uint64N(1<<47) &^ (hostarch.PageSize - 1)
		stubSysmsgStart := stubStart + 0x5000
		for _, test := range []struct {
			name string
			vars precompiledseccomp.Values
			fn   func(precompiledseccomp.Values) *seccomp.Program
		}{
			{stubfilter.StubProcessName, stubfilter.StubProcessVars(stubStart, stubROMapLen), stubfilter.StubProcess},
			{stubfilter.SysmsgThreadName, stubfilter.SysmsgThreadVars(stubStart, stubSysmsgStart), stubfilter.SysmsgThread},
			{stubfilter.SyscallThreadName, nil, stubfilter.SyscallThread},
		} {
			want, _, err := test.fn(test.vars).Build()
			if err != nil {
				t.Fatalf("%s (stubStart=%#x): cannot build program: %v", test.name, stubStart, err)
			}
			got := renderStubFilter(test.name, test.vars)
			if !slices.Equal(got, want) {
				t.Errorf("%s (stubStart=%#x): rendered precompiled program differs from compiled program:\ngot:  %v\nwant: %v", test.name, stubStart, got, want)
			}
			if prev, ok := rendered[test.name]; ok && test.vars != nil && slices.Equal(got, prev) {
				t.Errorf("%s: rendered program does not depend on stubStart=%#x", test.name, stubStart)
			}
			rendered[test.name] = got
		}
	}
}
