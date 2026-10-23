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

package kvm

import (
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

var (
	// precompiledProgramNames is the sorted list of all precompiled program
	// names. It is populated at generation time and used by `ListPrecompiled`.
	precompiledProgramNames = []string{
	"kvm_mmap_trap",
	}
)

// PrecompilationDisabledAtBuildTime is a constant that is used to
// indicate that precompilation was disabled at build time.
const PrecompilationDisabledAtBuildTime = false

// GetPrecompiled returns the precompiled program for the given name,
// and whether that program name exists.
func GetPrecompiled(programName string) (precompiledseccomp.Program, bool) {
	switch programName {
	case "kvm_mmap_trap":
		return precompiledseccomp.Program{
				Name: "kvm_mmap_trap",
				Bytecode32: []uint32{
					0x00000020,
					0x00000004,
					0x07000015,
					0xc000003e,
					0x00000020,
					0x00000000,
					0x05000015,
					0x00000009,
					0x00000020,
					0x00000020,
					0x00030045,
					0x00000004,
					0x00000020,
					0x00000028,
					0x00010045,
					0x00000800,
					0x00000006,
					0x00030000,
					0x00000006,
					0x7fff0000,
				},
				VarOffsets: map[string][]int{
				},
			}, true
	}
	return precompiledseccomp.Program{}, false
}

// ListPrecompiled returns a list of all registered program names.
func ListPrecompiled() []string {
	return append([]string(nil), precompiledProgramNames...)
}

