// Copyright 2023 The gVisor Authors.
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

//go:build !fuzz
// +build !fuzz

package secfuzz

import (
	"gvisor.dev/gvisor/pkg/bpf"
)

// Go does coverage-based fuzzing, so it discovers inputs that are
// "interesting" if they manage to cover new code.
// Go does not understand "BPF coverage", and there is no easy way to
// tell it that a certain BPF input has covered new lines of code.
// For this reason, this package has an auto-generated
// "secfuzz_covermeup.go" file which translates BPF code coverage into
// Go code coverage. However, it is huge and takes a long time to compile.
// For this reason, the file you're reading now acts as a stand-in for
// it which does not give the Go fuzzer any coverage-guidance.
// This is useful for fast builds and fuzz tests that don't need
// coverage-based guidance.

// countExecutedLinesProgram1 converts coverage data of the first BPF
// program to Go coverage data.
func countExecutedLinesProgram1(execution bpf.ExecutionMetrics, fuzzee *Fuzzee) {
	for i, covered := range execution.Coverage {
		if covered {
			fuzzee.coverage[i].Store(true)
		}
	}
}

// countExecutedLinesProgram2 converts coverage data of the second BPF
// program to Go coverage data.
func countExecutedLinesProgram2(execution bpf.ExecutionMetrics, fuzzee *Fuzzee) {
	for i, covered := range execution.Coverage {
		if covered {
			fuzzee.coverage[i].Store(true)
		}
	}
}
