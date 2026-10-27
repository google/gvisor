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

package ptrace

import (
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/platform/ptrace/stubfilter"
)

// TestStubFilterPrecompiled checks that the precompiled stub programs have
// the same bytecode as freshly compiled ones.
func TestStubFilterPrecompiled(t *testing.T) {
	for _, defaultAction := range stubfilter.DefaultActions {
		name := stubfilter.ProgramName(defaultAction)
		t.Run(name, func(t *testing.T) {
			want, _, err := stubfilter.Program(defaultAction).Build()
			if err != nil {
				t.Fatalf("cannot build program: %v", err)
			}
			program, ok := GetPrecompiled(name)
			if !ok {
				t.Fatalf("precompiled program not found")
			}
			got, err := program.RenderInstructions(nil)
			if err != nil {
				t.Fatalf("cannot render precompiled program: %v", err)
			}
			if !slices.Equal(got, want) {
				t.Errorf("precompiled program differs from compiled program:\ngot:  %v\nwant: %v", got, want)
			}
		})
	}
}
