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

	source, err := merge(flag.Args())
	if err != nil {
		fatalf("%v\n", err)
	}
	if err := os.WriteFile(*output, source, 0644); err != nil {
		fatalf("write: %v\n", err)
	}
}

// merge combines template sources in filename order. Declarations retain their
// original positions and comments; only imports are coalesced. In particular,
// separate init functions and methods must not be discarded based on their names.
func merge(paths []string) ([]byte, error) {
	var decls []ast.Decl
	comments := make(ast.CommentMap)
	fset := token.NewFileSet()
	var name string
	// Assign token positions in declaration order, independent of argument order.
	srcs := slices.Compact(slices.Sorted(slices.Values(paths)))
	for _, fname := range srcs {
		f, err := parser.ParseFile(fset, fname, nil, parser.ParseComments|parser.DeclarationErrors|parser.SpuriousErrors)
		if err != nil {
			return nil, err
		}
		if name == "" {
			name = f.Name.Name
		} else if name != f.Name.Name {
			return nil, fmt.Errorf("expected %q for package name instead of %q", name, f.Name.Name)
		}
		maps.Copy(comments, ast.NewCommentMap(fset, f, f.Comments))
		decls = append(decls, f.Decls...)
	}

	// Put imports first and remove redundant specs. Keep the original import
	// declarations so their comments retain valid positions within each file.
	imports := make(map[string]*ast.ImportSpec)
	newDecls := make([]ast.Decl, 0, len(decls))
	for _, d := range decls {
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
							return nil, fmt.Errorf("conflicting paths for import name %q: %q vs. %q", n, first, second)
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
	for _, d := range decls {
		if g, ok := d.(*ast.GenDecl); !ok || g.Tok != token.IMPORT {
			newDecls = append(newDecls, d)
		}
	}
	decls = newDecls

	// Infer build constraints for the output file.
	bcexpr, err := constraintutil.CombineFromFiles(srcs)
	if err != nil {
		return nil, fmt.Errorf("failed to read build constraints: %w", err)
	}

	// Print each declaration with only its own comments. Imports moved from
	// later files must not pull earlier declarations' inline annotations forward.
	// Template instances omit package documentation; build constraints are
	// reconstructed separately below.
	var buf bytes.Buffer
	_, _ = fmt.Fprintf(&buf, "package %s\n\n", name)
	for _, decl := range decls {
		if err := format.Node(&buf, fset, &printer.CommentedNode{
			Node:     decl,
			Comments: comments.Filter(decl).Comments(),
		}); err != nil {
			return nil, fmt.Errorf("formatting: %w", err)
		}
		_, _ = buf.WriteString("\n\n")
	}
	source, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting merged source: %w", err)
	}
	return append([]byte(constraintutil.Lines(bcexpr)), source...), nil
}
