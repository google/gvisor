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

package filter

import (
	"sort"

	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sync"
)

var (
	// precompiledPrograms holds registered programs.
	// It is populated in `registerPrograms`.
	precompiledPrograms map[string]precompiledseccomp.Program = nil

	// registerPrecompiledProgramsOnce ensures that program registration
	// happens only once.
	registerPrecompiledProgramsOnce sync.Once
)

// GetPrecompiled returns the precompiled program for the given name,
// and whether that program name exists.
func GetPrecompiled(programName string) (precompiledseccomp.Program, bool) {
	registerPrecompiledProgramsOnce.Do(registerPrograms)
	program, ok := precompiledPrograms[programName]
	return program, ok
}

// ListPrecompiled returns a list of all registered program names.
func ListPrecompiled() []string {
	registerPrecompiledProgramsOnce.Do(registerPrograms)
	programNames := make([]string, 0, len(precompiledPrograms))
	for name := range precompiledPrograms {
		programNames = append(programNames, name)
	}
	sort.Strings(programNames)
	return programNames
}

// registerPrograms registers available programs inside `precompiledPrograms`.
func registerPrograms() {
	programs := make(map[string]precompiledseccomp.Program)
	precompiledPrograms = programs
}

