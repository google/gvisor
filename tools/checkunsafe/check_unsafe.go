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

// Package checkunsafe allows unsafe imports only in files named appropriately.
package checkunsafe

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkunsafe",
	Doc:  "allows unsafe use only in specified files",
	Run:  run,
}

func run(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		for _, imp := range f.Imports {
			// Is this an unsafe import?
			pkg, err := strconv.Unquote(imp.Path.Value)
			if err != nil || pkg != "unsafe" {
				continue
			}

			// Extract the filename.
			filename := pass.Fset.File(imp.Pos()).Name()

			// Allow files named _unsafe.go or _test.go to opt out.
			if strings.HasSuffix(filename, "_unsafe.go") || strings.HasSuffix(filename, "_test.go") {
				continue
			}

			// Throw the error.
			pass.Reportf(imp.Pos(), fmt.Sprintf("package unsafe imported by %s; must end with _unsafe.go", path.Base(filename)))
		}
	}
	return nil, nil
}
