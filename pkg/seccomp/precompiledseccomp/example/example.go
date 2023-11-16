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

// Package example defines two seccomp programs ("example_program1" and
// "example_program2") to be embedded in the `usage` package in this
// directory.
package example

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// Variable names used in the precompiled programs.
// In this example, we have two file descriptors, which fit in 32 bits.
// If you need a 64-bit variable, simply declare two 32-bit variables and
// concatenate them to a single 64-bit number in the function that
// generates the `ProgramDesc`.
const (
	FD1 = "fd1"
	FD2 = "fd2"
)

// Name of the example programs.
const (
	// Program1Name is the name of the first example program.
	// It allows reading from `FD1` and `FD2`, but writing only to `FD1`.
	Program1Name = "example_program1"

	// Program2Name is the name of the second example program.
	// It allows reading from `FD1` and `FD2`, but writing only to `FD2`.
	Program2Name = "example_program2"
)

// Program1 returns a program that allows reading from FDs `FD1` and `FD2`,
// but writing only to FD `FD1`.
func Program1(values precompiledseccomp.Values) precompiledseccomp.ProgramDesc {
	return precompiledseccomp.ProgramDesc{
		Rules: []seccomp.RuleSet{{
			Rules: seccomp.NewSyscallRules().Add(
				unix.SYS_READ,
				seccomp.Or{
					seccomp.PerArg{seccomp.EqualTo(values[FD1])},
					seccomp.PerArg{seccomp.EqualTo(values[FD2])},
				},
			).Add(
				unix.SYS_WRITE,
				seccomp.PerArg{seccomp.EqualTo(values[FD1])},
			),
			Action: linux.SECCOMP_RET_ALLOW,
		}},
		SeccompOptions: seccomp.DefaultProgramOptions(),
	}
}

// Program2 returns a program that allows reading from FDs `FD1` and `FD2`,
// but writing only to FD `FD2`.
func Program2(values precompiledseccomp.Values) precompiledseccomp.ProgramDesc {
	return precompiledseccomp.ProgramDesc{
		Rules: []seccomp.RuleSet{{
			Rules: seccomp.NewSyscallRules().Add(
				unix.SYS_READ,
				seccomp.Or{
					seccomp.PerArg{seccomp.EqualTo(values[FD1])},
					seccomp.PerArg{seccomp.EqualTo(values[FD2])},
				},
			).Add(
				unix.SYS_WRITE,
				seccomp.PerArg{seccomp.EqualTo(values[FD2])},
			),
			Action: linux.SECCOMP_RET_ALLOW,
		}},
		SeccompOptions: seccomp.DefaultProgramOptions(),
	}
}

// PrecompiledPrograms defines the seccomp-bpf programs to precompile.
// This function is called by the generated `go_binary` rule.
func PrecompiledPrograms() ([]precompiledseccomp.Program, error) {
	vars := []string{FD1, FD2}
	example1, err := precompiledseccomp.Precompile(Program1Name, vars, Program1)
	if err != nil {
		return nil, err
	}
	example2, err := precompiledseccomp.Precompile(Program2Name, vars, Program2)
	if err != nil {
		return nil, err
	}
	return []precompiledseccomp.Program{example1, example2}, nil
}
