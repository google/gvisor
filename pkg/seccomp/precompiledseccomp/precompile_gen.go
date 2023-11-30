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

// precompile_gen generates a Go library that contains precompiled seccomp
// programs.
package main

import (
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/runsc/flag"

	// This import will be replaced by the one specified in the genrule,
	// or removed if stubbed out in fastbuild mode.
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp/example" // REPLACED_IMPORT_THIS_IS_A_LOAD_BEARING_COMMENT
)

//go:embed precompiled_lib.tmpl.go
var precompiledLibTemplate []byte

// Constants referring to how things are named in precompiled_lib.tmpl.go.
const (
	packageNameStandin            = "precompiled"
	precompiledseccompPackageName = "precompiledseccomp"
	registrationComment           = "PROGRAM_REGISTRATION_GOES_HERE_THIS_IS_A_LOAD_BEARING_COMMENT"
	programsMapVarName            = "programs"
)

// Flags.
var (
	output      = flag.String("out", "/dev/stdout", "output file")
	packageName = flag.String("package", "", "output package name")
)

// loadProgramsFn loads seccomp programs to be precompiled.
// It may be nil when it is stubbed out in fastbuild mode.
var loadProgramsFn = example.PrecompiledPrograms // PROGRAMS_FUNC_THIS_IS_A_LOAD_BEARING_COMMENT

func main() {
	flag.Parse()

	// Get a sorted list of programs.
	var programs []precompiledseccomp.Program
	if loadProgramsFn != nil {
		var err error
		programs, err = loadProgramsFn()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot get list of programs to precompile: %v\n", err)
			os.Exit(1)
		}
	}
	programNames := make(map[string]struct{}, len(programs))
	for _, program := range programs {
		if _, alreadySeen := programNames[program.Name]; alreadySeen {
			fmt.Fprintf(os.Stderr, "duplicate program name %q", program.Name)
			os.Exit(1)
		}
		programNames[program.Name] = struct{}{}
	}
	sort.Slice(programs, func(i, j int) bool {
		return programs[i].Name < programs[j].Name
	})

	// Open the output file.
	outFile, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open output file %q: %v\n", *output, err)
		os.Exit(1)
	}
	defer outFile.Close()

	// Write Go code to the output file.
	processedPackageComment := false
	packageStandinLine := fmt.Sprintf("package %s", packageNameStandin)
	packageCommentPrefix := fmt.Sprintf("// Package %s ", packageNameStandin)
	lines := strings.Split(string(precompiledLibTemplate), "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		switch {
		case line == packageStandinLine:
			fmt.Fprintf(outFile, "package %s\n", *packageName)
		case !processedPackageComment && strings.HasPrefix(line, packageCommentPrefix):
			// Do not output package comment, as this would conflict with
			// other package comments from other files in the same package.
			// Skip over all the next lines until we get to the "package" line.
			for ; i+1 < len(lines) && !strings.HasPrefix(lines[i+1], "package "); i++ {
			}
			processedPackageComment = true
		case strings.Contains(line, registrationComment):
			var indent string
			for {
				var found bool
				if line, found = strings.CutPrefix(line, "\t"); !found {
					break
				}
				indent += "\t"
			}
			for _, program := range programs {
				fmt.Fprint(outFile, program.Registration(indent, precompiledseccompPackageName, programsMapVarName))
			}
		default:
			fmt.Fprintf(outFile, "%s\n", line)
		}
	}
}
