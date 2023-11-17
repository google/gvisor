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
	"gvisor.dev/gvisor/runsc/boot/filter/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// Flags.
var (
	output        = flag.String("output", "fancy", "Output type: 'fancy' (human-readable with line numbers resolved), 'plain' (diffable but still human-readable output), 'bytecode' (dump raw bytecode)")
	nvproxy       = flag.Bool("nvproxy", false, "Enable nvproxy in filter configuration")
	denyAction    = flag.String("deny-action", "default", "What to do if the syscall matches the 'deny' ruleset (one of: errno, kill_process, kill_thread)")
	defaultAction = flag.String("default-action", "default", "What to do if all the syscall rules fail to match (one of: errno, kill_process, kill_thread)")
	badArchAction = flag.String("bad-arch-action", "default", "What to do if all the architecture field mismatches (one of: errno, kill_process, kill_thread)")
	out           = flag.String("out", "/dev/stdout", "Where to write the filter output (defaults to standard output)")
)

func action(s string) linux.BPFAction {
	switch s {
	case "default":
		def, err := seccomp.DefaultAction()
		if err != nil {
			log.Warningf("cannot determine default seccomp action: %v", err)
			os.Exit(1)
		}
		return def
	case "errno":
		return linux.SECCOMP_RET_ERRNO
	case "kill_process":
		return linux.SECCOMP_RET_KILL_PROCESS
	case "kill_thread":
		return linux.SECCOMP_RET_KILL_THREAD
	default:
		log.Warningf("invalid action %q (want one of: errno, kill_process, kill_thread)", s)
		os.Exit(1)
		panic("unreachable")
	}
}

func main() {
	flag.Parse()
	opt := config.Options{
		Platform: (&systrap.Systrap{}).SeccompInfo(),
		NVProxy:  *nvproxy,
	}
	rules, denyRules := config.Rules(opt)

	seccompOpts := config.SeccompOptions(opt)
	seccompOpts.DefaultAction = action(*defaultAction)
	seccompOpts.BadArchAction = action(*badArchAction)
	insns, stats, err := seccomp.BuildProgram([]seccomp.RuleSet{
		{
			Rules:  denyRules,
			Action: action(*denyAction),
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, seccompOpts)
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
	outFile, err := os.Create(*out)
	if err != nil {
		log.Warningf("cannot open output file %q: %v", *out, err)
		os.Exit(1)
	}
	defer outFile.Close()
	switch *output {
	case "fancy":
		dump, err := bpf.DecodeInstructions(insns)
		if err != nil {
			log.Warningf("%v", err)
			os.Exit(1)
		}
		fmt.Fprint(outFile, dump)
	case "plain":
		for _, ins := range insns {
			fmt.Fprint(outFile, ins.String())
		}
	case "bytecode":
		if _, err := outFile.WriteString(InstructionsToBytecode(insns)); err != nil {
			log.Warningf("cannot write bytecode to stdout: %v", err)
			os.Exit(1)
		}
	}
}
