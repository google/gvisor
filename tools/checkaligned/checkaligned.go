// Copyright 2022 The gVisor Authors.
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

// Package checkaligned ensures that atomic (u)int operations happen
// exclusively via the atomicbitops package.
//
// We support a "// +checkalignedignore" escape hatch in the package comment
// that disables checking throughout the package.
package checkaligned

import (
	"fmt"
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkaligned",
	Doc:  "prohibits direct use of atomic int operations",
	Run:  run,
}

// blocklist lists prohibited identifiers in the atomic package.
var blocklist = []string{
	"AddInt64",
	"AddUint64",
	"CompareAndSwapInt64",
	"CompareAndSwapUint64",
	"LoadInt64",
	"LoadUint64",
	"StoreInt64",
	"StoreUint64",
	"SwapInt64",
	"SwapUint64",

	"AddInt32",
	"AddUint32",
	"CompareAndSwapInt32",
	"CompareAndSwapUint32",
	"LoadInt32",
	"LoadUint32",
	"StoreInt32",
	"StoreUint32",
	"SwapInt32",
	"SwapUint32",
}

func run(pass *analysis.Pass) (any, error) {
	// Check for the "// +checkalignedignore" escape hatch.
	for _, file := range pass.Files {
		if file.Doc == nil {
			continue
		}
		for _, comment := range file.Doc.List {
			if len(comment.Text) > 2 && strings.HasPrefix(comment.Text[2:], " +checkalignedignore") {
				return nil, nil
			}
		}
	}

	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			// Only look at selector expressions (e.g. "foo.Bar").
			selExpr, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			// Package names are always identifiers and do not refer to objects.
			pkgIdent, ok := selExpr.X.(*ast.Ident)
			if !ok || pkgIdent.Obj != nil {
				return true
			}

			// Please don't trick this checker by renaming the atomic import.
			if pkgIdent.Name != "atomic" {
				return false
			}

			for _, blocked := range blocklist {
				if selExpr.Sel.Name == blocked {
					// All blocked functions end in Int32 or Uint32, which we can use to
					// suggest the correct type.
					typeNameLen := len("Int")
					if unsigned := "Uint"; strings.Contains(blocked, unsigned) {
						typeNameLen = len(unsigned)
					}
					typeNameLen += 2 // Account for the "32" or "64" suffix.
					typeName := blocked[len(blocked)-typeNameLen:]
					pass.Reportf(selExpr.Pos(), fmt.Sprintf("don't call atomic.%s; use atomicbitops.%s instead", blocked, typeName))
				}
			}

			return false
		})
	}

	return nil, nil
}
