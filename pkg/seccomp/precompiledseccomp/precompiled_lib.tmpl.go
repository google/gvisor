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

// GetPrecompiled returns the precompiled program for the given name,
// and whether that program name exists.
//
// Each program is constructed lazily in a `switch`, so that only the bytecode
// of the program being looked up is materialized (instead of eagerly
// allocating the bytecode of every precompiled program, which dominates
// sandbox startup time).
func GetPrecompiled(programName string) (precompiledseccomp.Program, bool) {
	switch programName {
	// PROGRAM_REGISTRATION_GOES_HERE_THIS_IS_A_LOAD_BEARING_COMMENT
	}
	return precompiledseccomp.Program{}, false
}

// ListPrecompiled returns a list of all registered program names.
func ListPrecompiled() []string {
	return append([]string(nil), precompiledProgramNames...)
}
