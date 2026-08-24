// Copyright 2018 The gVisor Authors.
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
	"go/printer"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"gvisor.dev/gvisor/tools/constraintutil"
)

var (
	output = flag.String("o", "", "output `file`")
)

func fatalf(s string, args ...any) {
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
	comments := make(ast.CommentMap)
	fset := token.NewFileSet()
	var name string
	// Match MergePackageFiles' declaration order when assigning token positions.
	srcs := slices.Sorted(slices.Values(flag.Args()))
	for _, fname := range srcs {
		f, err := parser.ParseFile(fset, fname, nil, parser.ParseComments|parser.DeclarationErrors|parser.SpuriousErrors)
		if err != nil {
			fatalf("%v\n", err)
		}
		maps.Copy(comments, ast.NewCommentMap(fset, f, f.Comments))

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

	// Put imports first and remove redundant specs. Keep the original import
	// declarations so their comments retain valid positions within each file.
	imports := make(map[string]*ast.ImportSpec)
	newDecls := make([]ast.Decl, 0, len(f.Decls))
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.IMPORT {
			specs := g.Specs[:0]
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
					specs = append(specs, i)
				} else {
					if i2, ok := imports[n]; ok {
						if first, second := i.Path.Value, i2.Path.Value; first != second {
							fatalf("Conflicting paths for import name '%s': '%s' vs. '%s'\n", n, first, second)
						}
					} else {
						imports[n] = i
						specs = append(specs, i)
					}
				}
			}
			if len(specs) > 0 {
				g.Specs = specs
				newDecls = append(newDecls, g)
			}
		}
	}
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); !ok || g.Tok != token.IMPORT {
			newDecls = append(newDecls, d)
		}
	}
	f.Decls = newDecls

	// Infer build constraints for the output file.
	bcexpr, err := constraintutil.CombineFromFiles(flag.Args())
	if err != nil {
		fatalf("Failed to read build constraints: %v\n", err)
	}

	// Print each declaration with only its own comments. Imports moved from
	// later files must not pull earlier declarations' inline annotations forward.
	// Template instances omit package documentation; build constraints are
	// reconstructed separately below.
	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "package %s\n\n", name)
	for _, decl := range f.Decls {
		if err := format.Node(&buf, fset, &printer.CommentedNode{
			Node:     decl,
			Comments: comments.Filter(decl).Comments(),
		}); err != nil {
			fatalf("formatting: %v\n", err)
		}
		_, _ = buf.WriteString("\n\n")
	}
	source, err := format.Source(buf.Bytes())
	if err != nil {
		fatalf("formatting merged source: %v\n", err)
	}
	outf, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fatalf("opening output: %v\n", err)
	}
	defer outf.Close()
	outf.WriteString(constraintutil.Lines(bcexpr))
	if _, err := outf.Write(source); err != nil {
		fatalf("write: %v\n", err)
	}
}
