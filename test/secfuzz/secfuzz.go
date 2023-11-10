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

// Package secfuzz allows fuzz-based testing of seccomp-bpf programs.
package secfuzz

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sync"
)

// Fuzzee wraps a program for the purpose of fuzzing.
type Fuzzee struct {
	// Name is a human-friendly name for the program.
	Name string

	// If `EnforceFullCoverage` is set, the fuzz test will
	// fail if any instruction in the program is not covered.
	// The caller must ensure that the seed corpus is sufficient
	// to fully cover the program.
	EnforceFullCoverage bool

	// Instructions is the set of instructions in the program.
	Instructions []bpf.Instruction

	coverage [bpf.MaxInstructions]atomicbitops.Bool
}

// DiffFuzzer fuzzes two seccomp programs.
type DiffFuzzer struct {
	// f is the Go fuzzer to use.
	f *testing.F

	// The two programs being differentially fuzzed.
	fuzzee1, fuzzee2 *Fuzzee

	compiled1, compiled2 bpf.Program
}

// String returns the program's name.
func (f *Fuzzee) String() string {
	return f.Name
}

// AddSeed adds the given syscall data to the fuzzer's seed corpus.
func (df *DiffFuzzer) AddSeed(scData linux.SeccompData) {
	df.f.Helper()

	// We represent the syscall arguments as two uint32s so that the fuzzer
	// can more easily notice that changing each half produces different
	// coverage. This is due to the fact that BPF only supports 32-bit
	// arithmetic, so it has to separately compare each 32-bit half of the
	// 64-bit numbers.
	df.f.Add(
		int32(scData.Nr),
		uint32(scData.Arch),
		uint32(scData.Args[0]>>32), uint32(scData.Args[0]), // arg0
		uint32(scData.Args[1]>>32), uint32(scData.Args[1]), // arg1
		uint32(scData.Args[2]>>32), uint32(scData.Args[2]), // arg2
		uint32(scData.Args[3]>>32), uint32(scData.Args[3]), // arg3
		uint32(scData.Args[4]>>32), uint32(scData.Args[4]), // arg4
		uint32(scData.Args[5]>>32), uint32(scData.Args[5]), // arg5
		uint32(scData.InstructionPointer>>32), uint32(scData.InstructionPointer), // rip
	)
}

// defaultSeedCorpus adds generally useful test cases to `f`'s seed corpus.
func (df *DiffFuzzer) defaultSeedCorpus() {
	df.f.Helper()

	// Seed the fuzzer with each syscall number.
	for sysno := 0; sysno <= sentry.MaxSyscallNum; sysno++ {
		// Add a test case for each syscall argument half to have
		// all bits set. This isn't perfect, but gives lots of
		// coverage cheaply.
		for i := -1; i < len(linux.SeccompData{}.Args); i++ {
			for _, argValue := range []uint64{
				0x0000000000000000,
				0xffffffff00000000,
				0x00000000ffffffff,
			} {
				data := linux.SeccompData{
					Nr:   int32(sysno),
					Arch: seccomp.LINUX_AUDIT_ARCH,
				}
				if i == -1 {
					data.InstructionPointer = argValue
				} else {
					data.Args[i] = argValue
				}
				df.AddSeed(data)
			}
		}
	}

	// Add a case for the invalid arch case.
	df.AddSeed(linux.SeccompData{
		Nr:   0,
		Arch: seccomp.LINUX_AUDIT_ARCH + 1,
	})

	// Add a case for an unknown syscall number.
	df.AddSeed(linux.SeccompData{
		Nr:   sentry.MaxSyscallNum + 1,
		Arch: seccomp.LINUX_AUDIT_ARCH,
	})

	// ALL THE BITS.
	df.AddSeed(linux.SeccompData{
		Nr:                 -1,
		Arch:               0xffffffff,
		InstructionPointer: 0xffffffffffffffff,
		Args: [6]uint64{
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0xffffffffffffffff,
		},
	})
}

// DeriveCorpusFromRuleSets attempts to extract useful seed corpus rules
// out of the given `RuleSet`s.
func (df *DiffFuzzer) DeriveCorpusFromRuleSets(ruleSets []seccomp.RuleSet) {
	for _, ruleSet := range ruleSets {
		for _, tc := range ruleSet.Rules.UsefulTestCases() {
			df.AddSeed(tc)
		}
	}
}

// NewDiffFuzzer creates a fuzzer that verifies that two seccomp-bpf programs
// are equivalent by fuzzing both of them with the same inputs and checking
// that they output the same result.
func NewDiffFuzzer(f *testing.F, fuzzee1, fuzzee2 *Fuzzee) (*DiffFuzzer, error) {
	f.Helper()
	if len(fuzzee1.Instructions) > bpf.MaxInstructions {
		return nil, fmt.Errorf("program %s has %d instructions, which exceeds the maximum of %d", fuzzee1.String(), len(fuzzee1.Instructions), bpf.MaxInstructions)
	}
	if len(fuzzee2.Instructions) > bpf.MaxInstructions {
		return nil, fmt.Errorf("program %s has %d instructions, which exceeds the maximum of %d", fuzzee2.String(), len(fuzzee2.Instructions), bpf.MaxInstructions)
	}
	compiled1, err := bpf.Compile(fuzzee1.Instructions, false)
	if err != nil {
		return nil, fmt.Errorf("failed to compile %s: %v", fuzzee1.String(), err)
	}
	compiled2, err := bpf.Compile(fuzzee2.Instructions, false)
	if err != nil {
		return nil, fmt.Errorf("failed to compile %s: %v", fuzzee2.String(), err)
	}
	df := &DiffFuzzer{
		f:         f,
		fuzzee1:   fuzzee1,
		fuzzee2:   fuzzee2,
		compiled1: compiled1,
		compiled2: compiled2,
	}
	df.defaultSeedCorpus()
	return df, nil
}

// Fuzz runs the fuzzer.
func (df *DiffFuzzer) Fuzz() {
	df.f.Helper()
	pool := sync.Pool{
		New: func() any {
			buf := make([]byte, (&linux.SeccompData{}).SizeBytes())
			return &buf
		},
	}
	df.f.Fuzz(func(
		t *testing.T,
		sysno int32,
		arch uint32,
		arg0_high uint32, arg0_low uint32,
		arg1_high uint32, arg1_low uint32,
		arg2_high uint32, arg2_low uint32,
		arg3_high uint32, arg3_low uint32,
		arg4_high uint32, arg4_low uint32,
		arg5_high uint32, arg5_low uint32,
		rip_high uint32, rip_low uint32,
	) {
		// Reconstruct seccomp data from the fuzzed arguments.
		scData := linux.SeccompData{
			Nr:                 sysno,
			Arch:               arch,
			InstructionPointer: uint64(rip_high)<<32 | uint64(rip_low),
			Args: [6]uint64{
				uint64(arg0_high)<<32 | uint64(arg0_low),
				uint64(arg1_high)<<32 | uint64(arg1_low),
				uint64(arg2_high)<<32 | uint64(arg2_low),
				uint64(arg3_high)<<32 | uint64(arg3_low),
				uint64(arg4_high)<<32 | uint64(arg4_low),
				uint64(arg5_high)<<32 | uint64(arg5_low),
			},
		}
		// We can't allocate this buffer outside of the `fuzz` method because
		// this inner function is called in multiple goroutines.
		// We use a pool instead.
		buf := pool.Get().(*[]byte)
		exec1, err := bpf.InstrumentedExec[bpf.NativeEndian](df.compiled1, seccomp.DataAsBPFInput(&scData, *buf))
		if err != nil {
			t.Fatalf("Failed to execute %s with data %s: %v", df.fuzzee1.String(), scData.String(), err)
		}
		exec2, err := bpf.InstrumentedExec[bpf.NativeEndian](df.compiled2, seccomp.DataAsBPFInput(&scData, *buf))
		if err != nil {
			t.Fatalf("Failed to execute %s with data %s: %v", df.fuzzee2.String(), scData.String(), err)
		}
		pool.Put(buf)
		if exec1.ReturnValue != exec2.ReturnValue {
			t.Errorf(
				"%s and %s return different results for %s: %s = %v, %s = %v",
				df.fuzzee1.String(), df.fuzzee2.String(),
				scData.String(),
				df.fuzzee1.String(), linux.BPFAction(exec1.ReturnValue),
				df.fuzzee2.String(), linux.BPFAction(exec2.ReturnValue),
			)
		}
		countExecutedLinesProgram1(exec1, df.fuzzee1)
		countExecutedLinesProgram2(exec2, df.fuzzee2)
	})
	notCovered1 := false
	for i := 0; i < len(df.fuzzee1.Instructions); i++ {
		if !df.fuzzee1.coverage[i].Load() {
			notCovered1 = true
			break
		}
	}
	notCovered2 := false
	for i := 0; i < len(df.fuzzee2.Instructions); i++ {
		if !df.fuzzee2.coverage[i].Load() {
			notCovered2 = true
			break
		}
	}
	if notCovered1 {
		if df.fuzzee1.EnforceFullCoverage {
			df.f.Errorf("Program %s not fully covered:", df.fuzzee1.String())
			for pc, ins := range df.fuzzee1.Instructions {
				if df.fuzzee1.coverage[pc].Load() {
					df.f.Errorf("         [OK] % 4d: %s", pc, ins.String())
				} else {
					df.f.Errorf("[NOT COVERED] % 4d: %s", pc, ins.String())
				}
			}
			df.f.Error("\n")
		} else {
			df.f.Logf("Program %s not fully covered (but coverage not enforced).", df.fuzzee1.String())
		}
	}
	if notCovered2 {
		if df.fuzzee2.EnforceFullCoverage {
			df.f.Errorf("Program %s not fully covered:", df.fuzzee2.String())
			for pc, ins := range df.fuzzee2.Instructions {
				if df.fuzzee2.coverage[pc].Load() {
					df.f.Errorf("         [OK] % 4d: %s", pc, ins.String())
				} else {
					df.f.Errorf("[NOT COVERED] % 4d: %s", pc, ins.String())
				}
			}
			df.f.Error("\n")
		} else {
			df.f.Logf("Program %s not fully covered (but coverage not enforced).", df.fuzzee2.String())
		}
	}
}
