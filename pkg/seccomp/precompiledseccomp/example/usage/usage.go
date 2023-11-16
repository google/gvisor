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

// Package usage shows how to use precompiled seccomp-bpf programs.
package usage

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp/example"
)

// LoadProgram1 loads the program1 program with the given FDs.
func LoadProgram1(fd1, fd2 uint32) []bpf.Instruction {
	program, ok := GetPrecompiled(example.Program1Name)
	if !ok {
		panic(fmt.Sprintf("precompiled program %q not found", example.Program1Name))
	}
	insns, err := program.RenderInstructions(precompiledseccomp.Values{
		example.FD1: fd1,
		example.FD2: fd2,
	})
	if err != nil {
		panic(fmt.Errorf("failed to render instructions of precompiled program %q: %v", example.Program1Name, err))
	}
	return insns
}

// LoadProgram2 loads the program2 program with the given FDs.
func LoadProgram2(fd1, fd2 uint32) []bpf.Instruction {
	program, ok := GetPrecompiled(example.Program2Name)
	if !ok {
		panic(fmt.Sprintf("precompiled program %q not found", example.Program2Name))
	}
	insns, err := program.RenderInstructions(precompiledseccomp.Values{
		example.FD1: fd1,
		example.FD2: fd2,
	})
	if err != nil {
		panic(fmt.Errorf("failed to render instructions of precompiled program %q: %v", example.Program2Name, err))
	}
	return insns
}
