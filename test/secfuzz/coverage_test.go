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

package secfuzz

import (
	"testing"

	"gvisor.dev/gvisor/pkg/bpf"
)

// The fuzz build uses distinct Go branches for each instruction. Check that
// they record exactly the visited instructions, including for partial blocks.
func TestInstructionCoverage(t *testing.T) {
	for _, program := range []struct {
		name   string
		record func(bpf.ExecutionMetrics, *Fuzzee)
	}{
		{"first", countExecutedLinesProgram1},
		{"second", countExecutedLinesProgram2},
	} {
		t.Run(program.name, func(t *testing.T) {
			const limit = bpf.MaxInstructions
			for _, n := range []int{0, 1, limit/2 - 1, limit / 2, limit/2 + 1, limit} {
				for parity := range 2 {
					visited := make([]bool, n)
					for pc := range visited {
						visited[pc] = pc%2 == parity
					}
					var f Fuzzee
					program.record(bpf.ExecutionMetrics{Coverage: visited}, &f)
					for pc := range f.coverage {
						want := pc < n && visited[pc]
						if got := f.coverage[pc].Load(); got != want {
							t.Fatalf("length %d, pc %d: recorded %t, want %t", n, pc, got, want)
						}
					}
				}
			}
		})
	}
}
