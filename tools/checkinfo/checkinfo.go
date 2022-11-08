// Copyright 2021 The gVisor Authors.
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

// Package checkinfo attaches basic info to types.
package checkinfo

import (
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkinfo",
	Doc:  "annotates types with basic information",
	Run:  run,
	FactTypes: []analysis.Fact{
		(*Align)(nil),
		(*Offset)(nil),
		(*Size)(nil),
		(*Value)(nil),
	},
}

// Align is a fact.
type Align int64

// AFact implements analysis.Fact.AFact.
func (*Align) AFact() {}

// Offset is a fact.
type Offset int64

// AFact implements analysis.Fact.AFact.
func (*Offset) AFact() {}

// Size is a fact.
type Size int64

// AFact implements analysis.Fact.AFact.
func (*Size) AFact() {}

// Value is a trivial fact.
type Value string

// AFact implements analysis.Fact.AFact.
func (*Value) AFact() {}

func walkObject(pass *analysis.Pass, obj types.Object) {
	switch x := obj.(type) {
	case *types.Const:
		// Add a special constant value. This is supported for
		// constants only, and appears as a "Value" fact.
		v := Value(x.Val().ExactString())
		pass.ExportObjectFact(obj, &v)
	case *types.PkgName:
		// Don't walk to other packages.
	case *types.Var:
		// Add information as a field.
		a := Align(pass.TypesSizes.Alignof(x.Type()))
		s := Size(pass.TypesSizes.Sizeof(x.Type()))
		pass.ExportObjectFact(obj, &a)
		pass.ExportObjectFact(obj, &s)
	case *types.TypeName:
		// Skip if just an alias, or if not underlying type. If it is
		// not an alias, then it must be package-local.
		typ := x.Type()
		if x.IsAlias() || typ == nil || typ.Underlying() == nil {
			break
		}
		// Add basic information.
		a := Align(pass.TypesSizes.Alignof(typ))
		s := Size(pass.TypesSizes.Sizeof(typ))
		pass.ExportObjectFact(obj, &a)
		pass.ExportObjectFact(obj, &s)
		// Recurse to fields if this is a definition.
		if structType, ok := typ.Underlying().(*types.Struct); ok {
			fields := make([]*types.Var, 0, structType.NumFields())
			for i := 0; i < structType.NumFields(); i++ {
				fieldObj := structType.Field(i)
				fields = append(fields, fieldObj)
				walkObject(pass, fieldObj)
			}
			offsets := pass.TypesSizes.Offsetsof(fields)
			for i, field := range fields {
				pass.ExportObjectFact(field, (*Offset)(&offsets[i]))
			}
		}
	case *types.Func:
		// Skip if no underlying type.
		if x.Type() == nil {
			break
		}
		// Recurse to all parameters.
		sig := x.Type().(*types.Signature)
		if recv := sig.Recv(); recv != nil {
			walkObject(pass, recv)
		}
		if params := sig.Params(); params != nil {
			for i := 0; i < params.Len(); i++ {
				walkObject(pass, params.At(i))
			}
		}
		if results := sig.Results(); results != nil {
			for i := 0; i < results.Len(); i++ {
				walkObject(pass, results.At(i))
			}
		}
		walkScope(pass, x.Scope())
	}
}

// walkScope recursively resolves a scope.
func walkScope(pass *analysis.Pass, scope *types.Scope) {
	for _, name := range scope.Names() {
		walkObject(pass, scope.Lookup(name))
	}
}

func run(pass *analysis.Pass) (any, error) {
	// Export all facts.
	walkScope(pass, pass.Pkg.Scope())
	return nil, nil
}
