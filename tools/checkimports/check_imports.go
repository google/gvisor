// Copyright 2019 The gVisor Authors.
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

// Package checkimports enforces restrictions on package imports.
package checkimports

import (
	"path"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkimports",
	Doc:  "enforces restrictions on package imports",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		for _, imp := range f.Imports {
			pkg, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			switch pkg {
			case "unsafe":
				filename := pass.Fset.File(imp.Pos()).Name()
				if !strings.HasSuffix(filename, "_unsafe.go") && !strings.HasSuffix(filename, "_test.go") {
					pass.Reportf(imp.Pos(), "package unsafe imported by %s; must end with _unsafe.go", path.Base(filename))
				}
			case "archive/zip":
				if pass.Pkg.Path() != "gvisor.dev/gvisor/pkg/zip" {
					pass.Reportf(imp.Pos(), "import gvisor.dev/gvisor/pkg/zip instead of archive/zip")
				}
			}
		}
	}
	return nil, nil
}
