// Copyright 2020 The gVisor Authors.
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

// Package checklocks performs lock analysis to identify and flag unprotected
// access to annotated fields.
//
// For detailed usage refer to README.md in the same directory.
package checklocks

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// Analyzer is the main entrypoint.
var Analyzer = &analysis.Analyzer{
	Name:     "checklocks",
	Doc:      "checks lock preconditions on functions and fields",
	Run:      run,
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes: []analysis.Fact{
		(*atomicAlignment)(nil),
		(*lockGuardFacts)(nil),
		(*lockFunctionFacts)(nil),
	},
}

// objectObservations tracks lock correlations.
type objectObservations struct {
	counts map[types.Object]int
	total  int
}

// passContext is a pass with additional expected failures.
type passContext struct {
	pass         *analysis.Pass
	failures     map[positionKey]*failData
	exemptions   map[positionKey]struct{}
	forced       map[positionKey]struct{}
	functions    map[*ssa.Function]struct{}
	observations map[types.Object]*objectObservations
}

// observationsFor retrieves observations for the given object.
func (pc *passContext) observationsFor(obj types.Object) *objectObservations {
	if pc.observations == nil {
		pc.observations = make(map[types.Object]*objectObservations)
	}
	oo, ok := pc.observations[obj]
	if !ok {
		oo = &objectObservations{
			counts: make(map[types.Object]int),
		}
		pc.observations[obj] = oo
	}
	return oo
}

// forAllGlobals applies the given function to all globals.
func (pc *passContext) forAllGlobals(fn func(ts *ast.ValueSpec)) {
	for _, f := range pc.pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.VAR {
				continue
			}
			for _, gs := range d.Specs {
				fn(gs.(*ast.ValueSpec))
			}
		}
	}
}

// forAllTypes applies the given function over all types.
func (pc *passContext) forAllTypes(fn func(ts *ast.TypeSpec)) {
	for _, f := range pc.pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.TYPE {
				continue
			}
			for _, gs := range d.Specs {
				fn(gs.(*ast.TypeSpec))
			}
		}
	}
}

// forAllFunctions applies the given function over all functions.
func (pc *passContext) forAllFunctions(fn func(fn *ast.FuncDecl)) {
	for _, f := range pc.pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			fn(d)
		}
	}
}

// run is the main entrypoint.
func run(pass *analysis.Pass) (interface{}, error) {
	pc := &passContext{
		pass:       pass,
		failures:   make(map[positionKey]*failData),
		exemptions: make(map[positionKey]struct{}),
		forced:     make(map[positionKey]struct{}),
		functions:  make(map[*ssa.Function]struct{}),
	}

	// Find all line failure annotations.
	pc.extractLineFailures()

	// Find all struct declarations and export relevant facts.
	pc.forAllGlobals(func(vs *ast.ValueSpec) {
		if ss, ok := vs.Type.(*ast.StructType); ok {
			structType := pc.pass.TypesInfo.TypeOf(vs.Type).Underlying().(*types.Struct)
			pc.structLockGuardFacts(structType, ss)
		}
		pc.globalLockGuardFacts(vs)
	})
	pc.forAllTypes(func(ts *ast.TypeSpec) {
		if ss, ok := ts.Type.(*ast.StructType); ok {
			structType := pc.pass.TypesInfo.TypeOf(ts.Name).Underlying().(*types.Struct)
			pc.structLockGuardFacts(structType, ss)
		}
	})

	// Check all alignments.
	pc.forAllTypes(func(ts *ast.TypeSpec) {
		typ, ok := pass.TypesInfo.TypeOf(ts.Name).(*types.Named)
		if !ok {
			return
		}
		pc.checkTypeAlignment(pass.Pkg, typ)
	})

	// Find all function declarations and export relevant facts.
	pc.forAllFunctions(func(fn *ast.FuncDecl) {
		pc.functionFacts(fn)
	})

	// Scan all code looking for invalid accesses.
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	for _, fn := range state.SrcFuncs {
		// Import function facts generated above.
		//
		// Note that anonymous(closures) functions do not have an
		// object but do show up in the SSA. They can only be invoked
		// by named functions in the package, and they are analyzing
		// inline on every call. Thus we skip the analysis here. They
		// will be hit on calls, or picked up in the pass below.
		if obj := fn.Object(); obj == nil {
			continue
		}
		var lff lockFunctionFacts
		pc.pass.ImportObjectFact(fn.Object(), &lff)

		// Check the basic blocks in the function.
		pc.checkFunction(nil, fn, &lff, nil, false /* force */)
	}
	for _, fn := range state.SrcFuncs {
		// Ensure all anonymous functions are hit. They are not
		// permitted to have any lock preconditions.
		if obj := fn.Object(); obj != nil {
			continue
		}
		var nolff lockFunctionFacts
		pc.checkFunction(nil, fn, &nolff, nil, false /* force */)
	}

	// Check for inferred checklocks annotations.
	pc.checkInferred()

	// Check for expected failures.
	pc.checkFailures()

	return nil, nil
}
