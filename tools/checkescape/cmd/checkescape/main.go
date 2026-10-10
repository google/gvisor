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

// goBuildArchive compiles the pkg under analysis into an archive file
// (except for the main pkg) so that "go tool objdump"
// (invoked by checkescape) has machine code to disassemble.
func goBuildArchive(pass *analysis.Pass) (string, error) {
	tmp, err := os.CreateTemp("", "checkescape-*.a")
	if err != nil {
		return "", err
	}
	tmp.Close()

	var (
		pkgName    = pass.Pkg.Name()
		importPath = pass.Pkg.Path()
		cmd        *exec.Cmd
	)
	if pkgName == "main" {
		cmd = exec.Command("go", "build", "-o", tmp.Name(), importPath)
	} else {
		cmd = exec.Command("go", "build", "-buildmode=archive", "-o", tmp.Name(), importPath)
	}

	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("cannot build archive from %q: %w", importPath, err)
	}
	return tmp.Name(), nil
}

func main() {
	// Reset the flags registered by nogo
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	singlechecker.Main(&analysis.Analyzer{
		Name:      "checkescape",
		Doc:       checkescape.Analyzer.Doc,
		Requires:  checkescape.Analyzer.Requires,
		FactTypes: checkescape.Analyzer.FactTypes,
		Run: func(pass *analysis.Pass) (any, error) {
			archivePath, err := goBuildArchive(pass)
			if err != nil {
				return nil, err
			}
			defer os.Remove(archivePath)

			f, err := os.Open(archivePath)
			if err != nil {
				return nil, err
			}
			defer f.Close()

			return checkescape.Analyzer.Run(pass, f)
		},
	})
}
