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

//go:build !false
// +build !false

package filter_fuzz_test

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot/filter/config"
	"gvisor.dev/gvisor/test/secfuzz"
)

// FuzzFilterAgainstGolden tests that the behavior of the generated
// seccomp-bpf program has not changed.
// This is useful when modifying the way that the seccomp-bpf program
// is built, not when modifying what rules the program is meant to enforce.
// If you are modifying the seccomp-bpf rules in such a way that you
// are expecting the set of allowed/disallowed syscalls to change,
// you can update the reference program using:
//
//	$ make seccomp-sentry-filters ARGS='--deny-action=errno --default-action=kill_thread --bad-arch-action=kill_process --output=bytecode --out=runsc/boot/filter/filter_fuzz_golden.bpf'
func FuzzFilterAgainstGolden(f *testing.F) {
	goldenProgPath, err := testutil.FindFile("runsc/boot/filter/filter_fuzz_golden.bpf")
	if err != nil {
		f.Fatalf("failed to find golden program: %v", err)
	}
	goldenProg, err := os.ReadFile(goldenProgPath)
	if err != nil {
		f.Fatalf("failed to read golden program: %v", err)
	}
	goldenInstructions, err := bpf.ParseBytecode(goldenProg)
	if err != nil {
		f.Fatalf("failed to parse golden program bytecode: %v", err)
	}
	goldenFuzzee := secfuzz.Fuzzee{
		Name:         "golden",
		Instructions: goldenInstructions,
		// TODO(b/298726675): Enforce full coverage with the optimized program
		// once confident that it works well.
		// This will ensure that the generated fuzz corpus is sufficient to
		// fully exhaust the golden program.
		EnforceFullCoverage: false,
	}

	filterOpts := config.Options{
		Platform: (&systrap.Systrap{}).SeccompInfo(),
	}
	rules, denyRules := config.Rules(filterOpts)
	ruleSets := []seccomp.RuleSet{
		{
			Rules:  denyRules,
			Action: linux.SECCOMP_RET_ERRNO,
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}
	opts := config.SeccompOptions(filterOpts)
	// We use unique actions here to be able to tell them apart.
	opts.DefaultAction = linux.SECCOMP_RET_KILL_THREAD
	opts.BadArchAction = linux.SECCOMP_RET_KILL_PROCESS
	current, _, err := seccomp.BuildProgram(ruleSets, opts)
	if err != nil {
		f.Fatalf("failed to build seccomp-bpf program: %v", err)
	}
	currentFuzzee := secfuzz.Fuzzee{
		Name:                "current",
		Instructions:        current,
		EnforceFullCoverage: true,
	}
	df, err := secfuzz.NewDiffFuzzer(f, &goldenFuzzee, &currentFuzzee)
	if err != nil {
		f.Fatalf("failed to create diff fuzzer: %v", err)
	}
	df.DeriveCorpusFromRuleSets(ruleSets)
	df.Fuzz()
}
