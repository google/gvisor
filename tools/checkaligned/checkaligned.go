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

// Package checkaligned ensures that atomic (u)int64 operations happen
// exclusively via the atomicbitops package.
package checkaligned

import (
	"fmt"
	"go/ast"

	"golang.org/x/tools/go/analysis"
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkaligned",
	Doc:  "prohibits direct use of 64 bit atomic operations",
	Run:  run,
}

// blocklist lists prohibited identifiers in the atomic package.
//
// TODO(b/228378998): We should do this for 32 bit values too. Can also further
// genericize this to ban other things we don't like (e.g. os.File).
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
}

func run(pass *analysis.Pass) (interface{}, error) {
	// atomicbitops uses 64 bit values safely.
	if pass.Pkg.Name() == "atomicbitops" {
		return nil, nil
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
					pass.Reportf(selExpr.Pos(), fmt.Sprintf("don't call atomic.%s; use the atomicbitops package instead", blocked))
				}
			}

			return false
		})
	}

	return nil, nil
}
