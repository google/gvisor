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

// dumpfilter dumps the seccomp-bpf program used by the Sentry.
package main

import (
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
	"gvisor.dev/gvisor/runsc/boot/filter"
	"gvisor.dev/gvisor/runsc/flag"
)

// Flags.
var (
	output  = flag.String("output", "fancy", "Output type: 'fancy' (human-readable with line numbers resolved), 'plain' (diffable but still human-readable output), 'bytecode' (dump raw bytecode)")
	nvproxy = flag.Bool("nvproxy", false, "Enable nvproxy in filter configuration")
)

func main() {
	flag.Parse()
	rules, denyRules := filter.Rules(filter.Options{
		Platform: &systrap.Systrap{},
		NVProxy:  *nvproxy,
	})
	insns, stats, err := seccomp.BuildProgram([]seccomp.RuleSet{
		{
			Rules:  denyRules,
			Action: linux.SECCOMP_RET_ERRNO,
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, seccomp.ProgramOptions{
		DefaultAction: linux.SECCOMP_RET_ERRNO,
		BadArchAction: linux.SECCOMP_RET_ERRNO,
	})
	if err != nil {
		log.Warningf("%v", err)
		os.Exit(1)
	}
	log.Infof("Size before optimizations: %d", stats.SizeBeforeOptimizations)
	log.Infof("Size after optimizations: %d", stats.SizeAfterOptimizations)
	log.Infof("Build duration: %v", stats.BuildDuration)
	log.Infof("Rule optimization passes duration: %v", stats.RuleOptimizeDuration)
	log.Infof("BPF optimization passes duration: %v", stats.BPFOptimizeDuration)
	log.Infof("Total duration: %v", stats.BuildDuration+stats.RuleOptimizeDuration+stats.BPFOptimizeDuration)
	switch *output {
	case "fancy":
		dump, err := bpf.DecodeInstructions(insns)
		if err != nil {
			log.Warningf("%v", err)
			os.Exit(1)
		}
		fmt.Print(dump)
	case "plain":
		for _, ins := range insns {
			fmt.Println(ins.String())
		}
	case "bytecode":
		if _, err := os.Stdout.WriteString(InstructionsToBytecode(insns)); err != nil {
			log.Warningf("cannot write bytecode to stdout: %v", err)
			os.Exit(1)
		}
	}
}
