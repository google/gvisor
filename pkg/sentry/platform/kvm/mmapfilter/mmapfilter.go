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

// Package mmapfilter defines the seccomp-bpf program that the KVM platform
// installs to trap host `mmap(2)` calls.
package mmapfilter

import (
	"fmt"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// ProgramName is the name of the precompiled program.
const ProgramName = "kvm_mmap_trap"

// Program returns the program that traps mmap system calls, which are then
// handled in the SIGSYS handler.
func Program(precompiledseccomp.Values) *seccomp.Program {
	return &seccomp.Program{
		RuleSets: []seccomp.RuleSet{{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_MMAP: seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.MaskedEqual(unix.PROT_EXEC, 0),
					/* MAP_DENYWRITE is ignored and used only for filtering. */
					seccomp.MaskedEqual(unix.MAP_DENYWRITE, 0),
				},
			}),
			Action: seccomp.Trap,
		}},
		Options: seccomp.ProgramOptions{
			DefaultAction: seccomp.Allow,
			BadArchAction: seccomp.Allow,
		},
	}
}

// PrecompiledPrograms returns the set of seccomp programs to precompile.
func PrecompiledPrograms() ([]precompiledseccomp.Program, error) {
	program, err := precompiledseccomp.Precompile(ProgramName, nil, Program)
	if err != nil {
		return nil, fmt.Errorf("cannot precompile seccomp program %q: %w", ProgramName, err)
	}
	return []precompiledseccomp.Program{program}, nil
}
