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

// Generate a Go unit test file that checks for `structs.HostLayout` usage.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

var (
	pkg     = flag.String("package", "", "Name of the Go library package")
	outPath = flag.String("out", "", "Output test file path")
)

func main() {
	flag.Parse()
	if *pkg == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: hostlayout -package <package> -out <output_test.go> src1.go src2.go -- lib.a lib.x")
		os.Exit(1)
	}

	var structs []string
	afterDashDash := false
	libraryImportPath := ""
	for _, srcPath := range flag.Args() {
		if srcPath == "--" {
			afterDashDash = true
			continue
		}
		if !afterDashDash {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, srcPath, nil, parser.ParseComments)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", srcPath, err)
				os.Exit(1)
			}
			for _, decl := range f.Decls {
				genDecl, ok := decl.(*ast.GenDecl)
				if !ok || genDecl.Tok != token.TYPE {
					continue
				}
				for _, spec := range genDecl.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					// Only check exported structs
					if !typeSpec.Name.IsExported() {
						continue
					}
					if _, ok := typeSpec.Type.(*ast.StructType); ok && !slices.Contains(structs, typeSpec.Name.Name) {
						// We check for slices.Contains because duplicates can happen,
						// for example due to files with conditional compilation directives.
						structs = append(structs, typeSpec.Name.Name)
					}
				}
			}
			continue
		}
		if !strings.HasSuffix(srcPath, ".a") && !strings.HasSuffix(srcPath, ".x") {
			continue
		}
		libraryImportPath = strings.TrimSuffix(strings.TrimSuffix(srcPath, ".a"), ".x")
	}
	if libraryImportPath == "" {
		fmt.Fprintf(os.Stderr, "Failed to find library import path\n")
		os.Exit(1)
	}

	if len(structs) == 0 {
		// No exported structs, create empty test file to satisfy build rules
		contents := `
package ` + filepath.Base(*pkg) + `_hostlayout_test

import (
	"testing"
)

func TestDummy(t *testing.T) {
	// Needed to avoid errors in case the package has no exported structs.
}
`
		if err := os.WriteFile(*outPath, []byte(contents), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write empty test file: %v\n", err)
			os.Exit(1)
		}
		return
	}

	tmplData, err := newTemplateData(filepath.Base(*pkg), libraryImportPath, structs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create template data: %v\n", err)
		os.Exit(1)
	}

	// Create output file
	outF, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	defer outF.Close()
	t := template.Must(template.New("test").Parse(testTmpl))
	if err := t.Execute(outF, tmplData); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to execute template: %v\n", err)
		os.Exit(1)
	}
}
