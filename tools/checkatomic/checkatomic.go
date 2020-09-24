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

// Package checkatomic performs atomic access analysis.
//
// Individual struct members may be protected by annotations that indicate
// how they must be accessed. These annotations are of the form:
//
//		type foo struct {
//			mu sync.Mutex
//
//			// +checkatomic
//			bar int32
//		}
//
// Note that these annotations only apply to struct members at this time,
// as this greatly simplifies the analysis.
//
// Furthermore, this package actually analyzes variables that may be accessed
// atomically coincidentally. When they are, they are flagged as atomic. If
// additional accesses are done non-atomically, they will be flagged.
package checkatomic

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// Analyzer is the main entrypoint.
var Analyzer = &analysis.Analyzer{
	Name:      "checkatomic",
	Doc:       "checks atomic accesses on annotated fields",
	Run:       run,
	Requires:  []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes: []analysis.Fact{(*atomicDisposition)(nil)},
}

// atomicDisposition is saved per field.
//
// This represents how the field must be accessed. It must either
// be non-atomic (default), atomic or ignored.
type atomicDisposition int

// AFact implements analysis.Fact.AFact.
func (*atomicDisposition) AFact() {}

const (
	atomicDisallow atomicDisposition = iota
	atomicRequired
	atomicIgnore
)

type exemption struct {
	filename string
	line     int
}

type passContext struct {
	pass       *analysis.Pass
	failures   map[types.Object]int
	exemptions map[exemption]struct{}
}

func (pc *passContext) maybeFail(pos token.Pos, obj types.Object, fmtStr string, v ...interface{}) {
	if count, ok := pc.failures[obj]; ok && count > 0 {
		pc.failures[obj] = count - 1
		return // Suppress failure.
	}
	position := pc.pass.Fset.Position(pos)
	if _, ok := pc.exemptions[exemption{
		filename: position.Filename,
		line:     position.Line,
	}]; ok {
		return // Exempt.
	}
	pc.pass.Reportf(pos, fmtStr, v...)
}

func (pc *passContext) extractAnnotations(field *ast.Field, fieldType *types.Var) (ad atomicDisposition) {
	if field.Doc == nil {
		return
	}
	for _, l := range field.Doc.List {
		if l.Text == "// +checkatomic" {
			if ad != atomicDisallow {
				pc.maybeFail(fieldType.Pos(), fieldType, "conflicting +checkatomic annotation")
			}
			ad = atomicRequired
		}
		if l.Text == "// +checkatomic:ignore" {
			if ad != atomicDisallow {
				pc.maybeFail(fieldType.Pos(), fieldType, "conflicting +checkatomic annotation")
			}
			ad = atomicIgnore
		}
		if l.Text == "// +checkatomic:fail" {
			// Add to the pass context. These will be matched and deleted
			// in the analysis pass. We annotate the number of times we expect.
			pc.failures[fieldType] = pc.failures[fieldType] + 1
		}
	}
	return
}

func (pc *passContext) checkAtomicCall(inst ssa.Instruction, ad atomicDisposition, obj types.Object) {
	switch x := inst.(type) {
	case *ssa.Call:
		if x.Common().IsInvoke() {
			// This is an illegal interface dispatch.
			if ad == atomicRequired {
				pc.maybeFail(inst.Pos(), obj, "dynamic dispatch with atomic-only field")
			}
			return
		}
		fn, ok := x.Common().Value.(*ssa.Function)
		if !ok {
			// This is an illegal call to a non-static function.
			if ad == atomicRequired {
				pc.maybeFail(inst.Pos(), obj, "dispatch to non-static function with atomic-only field")
			}
			return
		}
		pkg := fn.Package()
		if pkg == nil {
			// This is a call to some shared wrapper function.
			if ad == atomicRequired {
				pc.maybeFail(inst.Pos(), obj, "dispatch to shared function or wrapper")
			}
			return
		}
		if name := pkg.Pkg.Name(); name != "atomic" && name != "atomicbitops" {
			// This is an illegal call to a non-atomic package function.
			if ad == atomicRequired {
				pc.maybeFail(inst.Pos(), obj, "dispatch to non-atomic function with atomic-only field")
			}
			return
		}
		if ad == atomicDisallow {
			// It looks like this was dispatched to an atomic function. If
			// we don't expect this to be an atomic value, then we fail.
			pc.maybeFail(inst.Pos(), obj, "dispatch to atomic function with field missing +checkatomic")
		}
	default:
		// This is something else entirely.
		if ad == atomicRequired {
			pc.maybeFail(inst.Pos(), obj, "illegal use of atomic-only field by %T instruction", inst)
		}
	}
}

func findField(v ssa.Value, field int) types.Object {
	structType, ok := v.Type().Underlying().(*types.Struct)
	if !ok {
		structType = v.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct)
	}
	return structType.Field(field)
}

func freshAlloc(v ssa.Value) bool {
	switch x := v.(type) {
	case *ssa.Alloc:
		return true
	case *ssa.FieldAddr:
		return freshAlloc(x.X)
	case *ssa.Field:
		return freshAlloc(x.X)
	case *ssa.IndexAddr:
		return freshAlloc(x.X)
	case *ssa.Index:
		return freshAlloc(x.X)
	case *ssa.Convert:
		return freshAlloc(x.X)
	default:
		return false
	}
}

func isLocalAlloc(v ssa.Value) bool {
	switch x := v.(type) {
	case *ssa.Alloc:
		return true
	case *ssa.Field:
		return isLocalAlloc(x.X)
	case *ssa.FieldAddr:
		return isLocalAlloc(x.X)
	case *ssa.Index:
		return isLocalAlloc(x.X)
	case *ssa.IndexAddr:
		return isLocalAlloc(x.X)
	case *ssa.Convert:
		return isLocalAlloc(x.X)
	default:
		return false
	}
}

func (pc *passContext) checkInstruction(inst ssa.Instruction) {
	var ad atomicDisposition // Used below.
	switch x := inst.(type) {
	case *ssa.Field:
		// Ignore failure; mustBeAtomic defaults to false.
		obj := findField(x.X, x.Field)
		pc.pass.ImportObjectFact(obj, &ad)

		// This is a value access, which we consider disallowed. It
		// doesn't matter what the downstream instructions are.
		if refs := x.Referrers(); refs != nil && len(*refs) > 0 && ad == atomicRequired && !freshAlloc(x.X) {
			pc.maybeFail(inst.Pos(), obj, "accessing atomic-only field non-atomically")
		}
	case *ssa.FieldAddr:
		// If this is derived from a local allocation, disregard.
		if isLocalAlloc(x) {
			return
		}

		// See above, re: default.
		obj := findField(x.X, x.Field)
		pc.pass.ImportObjectFact(obj, &ad)

		// Need to check all relevant instructions. We accept only calls
		// to functions in the atomic package.
		if refs := x.Referrers(); refs != nil {
			for _, otherInst := range *refs {
				pc.checkAtomicCall(otherInst, ad, obj)
			}
		}
	}
}

func (pc *passContext) checkBasicBlock(block *ssa.BasicBlock) {
	for _, inst := range block.Instrs {
		pc.checkInstruction(inst)
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	pc := passContext{
		pass:       pass,
		failures:   make(map[types.Object]int),
		exemptions: make(map[exemption]struct{}),
	}

	// Generate all annotations for facts.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.TYPE {
				continue
			}

			for _, gs := range d.Specs {
				ts := gs.(*ast.TypeSpec)
				ss, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				structType := pass.TypesInfo.TypeOf(ts.Name).Underlying().(*types.Struct)
				for i, field := range ss.Fields.List {
					ad := pc.extractAnnotations(field, structType.Field(i)) // May add failure.
					pass.ExportObjectFact(structType.Field(i), &ad)
				}
			}
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "// checkatomic:") {
					position := pass.Fset.Position(c.Pos())
					pc.exemptions[exemption{
						filename: position.Filename,
						line:     position.Line,
					}] = struct{}{}
				}
			}
		}
	}

	// Scan all code, looking for invalid instructions. Since we can't scan the
	// assembly code in the atomic package, we can actually detect an invalid
	// access merely through the presence of a ssa.Field operation on the field,
	// or an ssa.FieldAddr operation that is not used directly in a call to an
	// atomic function.
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	for _, fn := range state.SrcFuncs {
		if fn.Recover != nil {
			pc.checkBasicBlock(fn.Recover)
		}
		for _, block := range fn.Blocks {
			pc.checkBasicBlock(block)
		}
	}

	// Scan for remaining failures we expect.
	for obj, count := range pc.failures {
		if count > 0 {
			// We are missing expect failures, report as much as possible.
			pass.Reportf(obj.Pos(), "missing %d failures for %s", count, obj)
		}
	}

	// Scan all functions for violations.
	return nil, nil
}
