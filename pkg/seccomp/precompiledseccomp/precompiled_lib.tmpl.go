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

// Package precompiled does not exist. This file is used in a go:embed
// directive inside `precompile_gen.go`.
package precompiled

import (
	"runtime"

	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

var (
	// precompiledProgramNames is the sorted list of all precompiled program
	// names. It is populated at generation time and used by `ListPrecompiled`.
	precompiledProgramNames = []string{
		// PROGRAM_NAMES_LIST_GOES_HERE_THIS_IS_A_LOAD_BEARING_COMMENT
	}
)

// PrecompilationDisabledAtBuildTime is a constant that is used to
// indicate that precompilation was disabled at build time.
const PrecompilationDisabledAtBuildTime = false // PRECOMPILATION_DISABLED_AT_BUILD_TIME_THIS_IS_A_LOAD_BEARING_COMMENT

// precompiledArch is the GOARCH of the generator that wrote this file, which
// is the architecture the programs above were compiled for.
const precompiledArch = "" // PRECOMPILED_ARCH_THIS_IS_A_LOAD_BEARING_COMMENT

// GetPrecompiled returns the precompiled program for the given name,
// and whether that program name exists for this architecture.
func GetPrecompiled(programName string) (precompiledseccomp.Program, bool) {
	// Programs compiled for another architecture would be wrong here. The go
	// branch carries files that a single amd64 build generated.
	if runtime.GOARCH != precompiledArch {
		return precompiledseccomp.Program{}, false
	}
	switch programName {
	// PROGRAM_REGISTRATION_GOES_HERE_THIS_IS_A_LOAD_BEARING_COMMENT
	}
	return precompiledseccomp.Program{}, false
}

// ListPrecompiled returns a list of all registered program names for this
// architecture.
func ListPrecompiled() []string {
	if runtime.GOARCH != precompiledArch {
		return nil
	}
	return append([]string(nil), precompiledProgramNames...)
}
