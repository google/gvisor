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

// Package secbenchdef contains struct definitions for secbench benchmarks.
// All structs in this package need to be JSON-serializable.
package secbenchdef

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Bench represents a benchmark to run.
type Bench struct {
	// Name is the name of the benchmark.
	Name string `json:"name"`
	// Profile represents the syscall pattern profile being benchmarked.
	Profile Profile `json:"profile"`
	// Instructions is the seccomp-bpf program to run the benchmark with.
	Instructions []bpf.Instruction `json:"instructions"`
	// BuildStats contains information on timing and size of the program.
	BuildStats seccomp.BuildStats `json:"buildStats"`
	// AllowRejected can be set to true if some sequences in the application
	// profile are expected to not be allowed.
	// If this is the case, the program's overall performance will not be
	// reported.
	AllowRejected bool `json:"allowRejected"`
}

// Profile represents an application's syscall profile.
type Profile struct {
	// Arch is the architecture of the application.
	// Should be an AUDIT_ARCH_* value.
	Arch uint32 `json:"arch"`
	// Sequences is a set of weighted syscall sequences.
	// A benchmark with a given Profile will run these sequences
	// picked by weighted random choice.
	Sequences []Sequence `json:"sequences"`
}

// Sequence is a syscall sequence that the benchmark will make.
type Sequence struct {
	// Name is the name of the sequence.
	Name string `json:"name"`
	// Weight is the weight of the sequence relative to all others within the
	// same Profile.
	Weight int `json:"weight"`
	// Syscalls is the set of syscalls of the sequence.
	Syscalls []Syscall `json:"syscalls"`
}

// String returns the name of the Sequence.
func (s Sequence) String() string {
	return s.Name
}

const (
	// NonExistentFD is an FD that is overwhelmingly likely to not exist,
	// because it would mean that the application has opened 2^31-1 FDs.
	// Useful to make sure syscalls involving FDs don't actually
	// do anything serious.
	NonExistentFD = uintptr(0x7fffffff)

	// BadFD can be used as an invalid FD in syscall arguments.
	BadFD = uintptr(0x80000000)
)

// Syscall is a single syscall within a Sequence.
type Syscall struct {
	// Special may be set for syscalls with special handling.
	// If set, this takes precedence over the other fields.
	Special SpecialSyscall `json:"special,omitempty"`
	// Sysno is the syscall number.
	Sysno uintptr `json:"sysno"`
	// Args is the syscall arguments.
	Args [6]uintptr `json:"args"`
}

// Sys is a helper function to create a Syscall struct.
func Sys(sysno uintptr, args ...uintptr) Syscall {
	if len(args) > 6 {
		panic(fmt.Sprintf("cannot pass more than 6 syscall arguments, got: %v", args))
	}
	var sixArgs [6]uintptr
	for i := 0; i < len(args); i++ {
		sixArgs[i] = args[i]
	}
	return Syscall{
		Sysno: sysno,
		Args:  sixArgs,
	}
}

// Single takes in a single syscall data and returns a one-item Syscall slice.
func Single(sysno uintptr, args ...uintptr) []Syscall {
	return []Syscall{Sys(sysno, args...)}
}

// Call calls the system call.
//
//go:nosplit
func (s *Syscall) Call() (r1 uintptr, r2 uintptr, err error) {
	if s.Special != "" {
		return s.Special.Call()
	}
	return unix.Syscall6(s.Sysno, s.Args[0], s.Args[1], s.Args[2], s.Args[3], s.Args[4], s.Args[5])
}

// BenchRunRequest encodes a request sent to the benchmark runner binary.
type BenchRunRequest struct {
	// Bench is the benchmark being run.
	Bench Bench `json:"bench"`
	// Iterations is the number of iterations to do (b.N).
	Iterations uint64 `json:"iterations"`
	// RandomSeed is the random seed to use to pick sequences.
	RandomSeed int64 `json:"randomSeed"`
	// ActiveSequences[i] is true if Bench.Profile.Sequences[i] should be
	// run.
	ActiveSequences []bool `json:"activeSequences"`
	// InstallFilter is true if the seccomp-bpf filter should be actually
	// installed. Setting this to false allows measuring the filter-less
	// performance, so that it can be subtracted from performance with the
	// filter.
	InstallFilter bool `json:"installFilter"`
}

// SequenceMetrics is the per-sequence part of BenchRunResponse.
type SequenceMetrics struct {
	Iterations uint64 `json:"iterations"`
	TotalNanos uint64 `json:"totalNanos"`
}

// BenchRunResponse encodes a response from the runner binary.
type BenchRunResponse struct {
	// TotalNanos is the number of nanoseconds that the whole run took.
	TotalNanos uint64 `json:"totalNanos"`

	// SequenceMetrics is the per-sequence metrics, mapped by index against
	// the sequences in the Profile.
	SequenceMetrics []SequenceMetrics `json:"sequenceMetrics"`
}
