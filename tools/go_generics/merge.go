// Copyright 2018 Google LLC
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

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
)

var (
	output = flag.String("o", "", "output `file`")
)

func fatalf(s string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, s, args...)
	os.Exit(1)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <input1> [<input2> ...]\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if *output == "" || len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Load all files.
	files := make(map[string]*ast.File)
	fset := token.NewFileSet()
	var name string
	for _, fname := range flag.Args() {
		f, err := parser.ParseFile(fset, fname, nil, parser.ParseComments|parser.DeclarationErrors|parser.SpuriousErrors)
		if err != nil {
			fatalf("%v\n", err)
		}

		files[fname] = f
		if name == "" {
			name = f.Name.Name
		} else if name != f.Name.Name {
			fatalf("Expected '%s' for package name instead of '%s'.\n", name, f.Name.Name)
		}
	}

	// Merge all files into one.
	pkg := &ast.Package{
		Name:  name,
		Files: files,
	}
	f := ast.MergePackageFiles(pkg, ast.FilterUnassociatedComments|ast.FilterFuncDuplicates|ast.FilterImportDuplicates)

	// Create a new declaration slice with all imports at the top, merging any
	// redundant imports.
	imports := make(map[string]*ast.ImportSpec)
	var anonImports []*ast.ImportSpec
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.IMPORT {
			for _, s := range g.Specs {
				i := s.(*ast.ImportSpec)
				p, _ := strconv.Unquote(i.Path.Value)
				var n string
				if i.Name == nil {
					n = filepath.Base(p)
				} else {
					n = i.Name.Name
				}
				if n == "_" {
					anonImports = append(anonImports, i)
				} else {
					if i2, ok := imports[n]; ok {
						if first, second := i.Path.Value, i2.Path.Value; first != second {
							fatalf("Conflicting paths for import name '%s': '%s' vs. '%s'\n", n, first, second)
						}
					} else {
						imports[n] = i
					}
				}
			}
		}
	}
	newDecls := make([]ast.Decl, 0, len(f.Decls))
	if l := len(imports) + len(anonImports); l > 0 {
		// Non-NoPos Lparen is needed for Go to recognize more than one spec in
		// ast.GenDecl.Specs.
		d := &ast.GenDecl{
			Tok:    token.IMPORT,
			Lparen: token.NoPos + 1,
			Specs:  make([]ast.Spec, 0, l),
		}
		for _, i := range imports {
			d.Specs = append(d.Specs, i)
		}
		for _, i := range anonImports {
			d.Specs = append(d.Specs, i)
		}
		newDecls = append(newDecls, d)
	}
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); !ok || g.Tok != token.IMPORT {
			newDecls = append(newDecls, d)
		}
	}
	f.Decls = newDecls

	// Write the output file.
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, f); err != nil {
		fatalf("%v\n", err)
	}

	if err := ioutil.WriteFile(*output, buf.Bytes(), 0644); err != nil {
		fatalf("%v\n", err)
	}
}
