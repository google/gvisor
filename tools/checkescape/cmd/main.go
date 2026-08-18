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

// Binary checkescape is a `vettool` for `go vet`.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/singlechecker"

	"gvisor.dev/gvisor/tools/checkescape"
)

// goBuild compiles the pkg under analysis into a standalone binary
// so that "go tool objdump" (invoked by checkescape) has machine code to disassemble.
func goBuild(pass *analysis.Pass) (string, error) {
	tmp, err := os.CreateTemp("", "checkescape-*.bin")
	if err != nil {
		return "", err
	}
	tmp.Close()

	importPath := pass.Pkg.Path()
	cmd := exec.Command("go", "build", "-o", tmp.Name(), importPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("cannot build bin from %q: %w", importPath, err)
	}
	return tmp.Name(), nil
}

func main() {
	// Reset the flags registered by nogo
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.CommandLine.Usage = func() {}

	singlechecker.Main(&analysis.Analyzer{
		Name:      "checkescape",
		Doc:       checkescape.Analyzer.Doc,
		Requires:  checkescape.Analyzer.Requires,
		FactTypes: checkescape.Analyzer.FactTypes,
		Run: func(pass *analysis.Pass) (any, error) {
			binPath, err := goBuild(pass)
			if err != nil {
				return nil, err
			}
			defer os.Remove(binPath)

			f, err := os.Open(binPath)
			if err != nil {
				return nil, err
			}
			defer f.Close()

			return checkescape.Analyzer.Run(pass, f)
		},
	})
}
