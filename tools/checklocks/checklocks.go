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
// access to field annotated with a '// +checklocks:<mutex-name>' annotation.
//
// For detailed ussage refer to README.md in the same directory.
package checklocks

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	checkLocksAnnotation = "// +checklocks:"
	checkLocksIgnore     = "// +checklocksignore"
	checkLocksFail       = "// +checklocksfail"
)

// Analyzer is the main entrypoint.
var Analyzer = &analysis.Analyzer{
	Name:      "checklocks",
	Doc:       "checks lock preconditions on functions and fields",
	Run:       run,
	Requires:  []*analysis.Analyzer{buildssa.Analyzer},
	FactTypes: []analysis.Fact{(*lockFieldFacts)(nil), (*lockFunctionFacts)(nil)},
}

// lockFieldFacts apply on every struct field protected by a lock or that is a
// lock.
type lockFieldFacts struct {
	// GuardedBy tracks the names and field numbers that guard this field.
	GuardedBy map[string]int

	// IsMutex is true if the field is of type sync.Mutex.
	IsMutex bool

	// IsRWMutex is true if the field is of type sync.RWMutex.
	IsRWMutex bool

	// FieldNumber is the number of this field in the struct.
	FieldNumber int
}

// AFact implements analysis.Fact.AFact.
func (*lockFieldFacts) AFact() {}

type functionGuard struct {
	// ParameterNumber is the index of the object that contains the guarding mutex.
	// This is required during SSA analysis as field names and parameters names are
	// not available in SSA. For example, from the example below ParameterNumber would
	// be 1 and FieldNumber would correspond to the field number of 'mu' within b's type.
	//
	// //+checklocks:b.mu
	// func (a *A) method(b *B, c *C) {
	//   ...
	// }
	ParameterNumber int

	// FieldNumber is the field index of the mutex in the parameter's struct
	// type. Refer to example above for more details.
	FieldNumber int
}

// lockFunctionFacts apply on every method.
type lockFunctionFacts struct {
	// GuardedBy tracks the names and number of parameter (including receiver)
	// lockFuncfields that guard calls to this function.
	// The key is the name specified in the checklocks annotation. e.g given
	// the following code.
	// ```
	// type A struct {
	//   mu sync.Mutex
	//   a int
	// }
	//
	// // +checklocks:a.mu
	// func xyz(a *A) {..}
	// ```
	//
	// '`+checklocks:a.mu' will result in an entry in this map as shown below.
	// GuardedBy: {"a.mu" => {ParameterNumber: 0, FieldNumber: 0}
	GuardedBy map[string]functionGuard
}

// AFact implements analysis.Fact.AFact.
func (*lockFunctionFacts) AFact() {}

type positionKey string

// toPositionKey converts from a token.Position to a key we can use to track
// failures as the position of the failure annotation is not the same as the
// position of the actual failure (different column/offsets). Hence we ignore
// these fields and only use the file/line numbers to track failures.
func toPositionKey(position token.Position) positionKey {
	return positionKey(fmt.Sprintf("%s:%d", position.Filename, position.Line))
}

type failData struct {
	pos   token.Pos
	count int
}

func (f failData) String() string {
	return fmt.Sprintf("pos: %d, count: %d", f.pos, f.count)
}

type passContext struct {
	pass *analysis.Pass

	// exemptions tracks functions that should be exempted from lock checking due
	// to '// +checklocksignore' annotation.
	exemptions map[types.Object]struct{}

	failures map[positionKey]*failData
}

var (
	mutexRE   = regexp.MustCompile("((.*/)|^)sync.(CrossGoroutineMutex|Mutex)")
	rwMutexRE = regexp.MustCompile("((.*/)|^)sync.(CrossGoroutineRWMutex|RWMutex)")
)

func (pc *passContext) extractFieldAnnotations(field *ast.Field, fieldType *types.Var) *lockFieldFacts {
	s := fieldType.Type().String()
	// We use HasSuffix below because fieldType can be fully qualified with the
	// package name eg for the gvisor sync package mutex fields have the type:
	// "<package path>/sync/sync.Mutex"
	switch {
	case mutexRE.Match([]byte(s)):
		return &lockFieldFacts{IsMutex: true}
	case rwMutexRE.Match([]byte(s)):
		return &lockFieldFacts{IsRWMutex: true}
	default:
	}
	if field.Doc == nil {
		return nil
	}
	fieldFacts := &lockFieldFacts{GuardedBy: make(map[string]int)}
	for _, l := range field.Doc.List {
		if strings.HasPrefix(l.Text, checkLocksAnnotation) {
			guardName := strings.TrimPrefix(l.Text, checkLocksAnnotation)
			if _, ok := fieldFacts.GuardedBy[guardName]; ok {
				pc.pass.Reportf(field.Pos(), "annotation %s specified more than once.", l.Text)
				continue
			}
			fieldFacts.GuardedBy[guardName] = -1
		}
	}

	return fieldFacts
}

func (pc *passContext) findField(v ssa.Value, fieldNumber int) types.Object {
	structType, ok := v.Type().Underlying().(*types.Struct)
	if !ok {
		structType = v.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Struct)
	}
	return structType.Field(fieldNumber)
}

// findAndExportStructFacts finds any struct fields that are annotated with the
// "// +checklocks:" annotation and exports relevant facts about the fields to
// be used in later analysis.
func (pc *passContext) findAndExportStructFacts(ss *ast.StructType, structType *types.Struct) {
	type fieldRef struct {
		fieldObj *types.Var
		facts    *lockFieldFacts
	}
	mutexes := make(map[string]*fieldRef)
	rwMutexes := make(map[string]*fieldRef)
	guardedFields := make(map[string]*fieldRef)
	for i, field := range ss.Fields.List {
		fieldObj := structType.Field(i)
		fieldFacts := pc.extractFieldAnnotations(field, fieldObj)
		if fieldFacts == nil {
			continue
		}
		fieldFacts.FieldNumber = i

		ref := &fieldRef{fieldObj, fieldFacts}
		if fieldFacts.IsMutex {
			mutexes[fieldObj.Name()] = ref
		}
		if fieldFacts.IsRWMutex {
			rwMutexes[fieldObj.Name()] = ref
		}
		if len(fieldFacts.GuardedBy) != 0 {
			guardedFields[fieldObj.Name()] = ref
		}
	}

	// Export facts about all mutexes.
	for _, f := range mutexes {
		pc.pass.ExportObjectFact(f.fieldObj, f.facts)
	}
	// Export facts about all rwMutexes.
	for _, f := range rwMutexes {
		pc.pass.ExportObjectFact(f.fieldObj, f.facts)
	}

	// Validate that guarded fields annotations refer to actual mutexes or
	// rwMutexes in the struct.
	for _, gf := range guardedFields {
		for g := range gf.facts.GuardedBy {
			if f, ok := mutexes[g]; ok {
				gf.facts.GuardedBy[g] = f.facts.FieldNumber
			} else if f, ok := rwMutexes[g]; ok {
				gf.facts.GuardedBy[g] = f.facts.FieldNumber
			} else {
				pc.maybeFail(gf.fieldObj.Pos(), false /* isExempted */, "invalid mutex guard, no such mutex %s in struct %s", g, structType.String())
				continue
			}
			// Export guarded field fact.
			pc.pass.ExportObjectFact(gf.fieldObj, gf.facts)
		}
	}
}

func (pc *passContext) findAndExportFuncFacts(d *ast.FuncDecl) {
	log.Debugf("finding and exporting function facts\n")
	// for each function definition, check for +checklocks:mu annotation, which
	// means that the function must be called with that lock held.
	fnObj := pc.pass.TypesInfo.ObjectOf(d.Name)
	funcFacts := lockFunctionFacts{GuardedBy: make(map[string]functionGuard)}
	var (
		ignore    bool
		ignorePos token.Pos
	)

outerLoop:
	for _, l := range d.Doc.List {
		if strings.HasPrefix(l.Text, checkLocksIgnore) {
			pc.exemptions[fnObj] = struct{}{}
			ignore = true
			ignorePos = l.Pos()
			continue
		}
		if strings.HasPrefix(l.Text, checkLocksAnnotation) {
			guardName := strings.TrimPrefix(l.Text, checkLocksAnnotation)
			if _, ok := funcFacts.GuardedBy[guardName]; ok {
				pc.pass.Reportf(l.Pos(), "annotation %s specified more than once.", l.Text)
				continue
			}

			found := false
			x := strings.Split(guardName, ".")
			if len(x) != 2 {
				pc.pass.Reportf(l.Pos(), "checklocks mutex annotation should be of the form 'a.b'")
				continue
			}
			paramName, fieldName := x[0], x[1]
			log.Debugf("paramName: %s, fieldName: %s", paramName, fieldName)
			var paramList []*ast.Field
			if d.Recv != nil {
				paramList = append(paramList, d.Recv.List...)
			}
			if d.Type.Params != nil {
				paramList = append(paramList, d.Type.Params.List...)
			}
			for paramNum, field := range paramList {
				log.Debugf("field names: %+v", field.Names)
				if len(field.Names) == 0 {
					log.Debugf("skipping because parameter is unnamed", paramName)
					continue
				}
				nameExists := false
				for _, name := range field.Names {
					if name.Name == paramName {
						nameExists = true
					}
				}
				if !nameExists {
					log.Debugf("skipping because parameter name(s) does not match : %s", paramName)
					continue
				}
				ptrType, ok := pc.pass.TypesInfo.TypeOf(field.Type).Underlying().(*types.Pointer)
				if !ok {
					// Since mutexes cannot be copied we only care about parameters that
					// are pointer types when checking for guards.
					pc.pass.Reportf(l.Pos(), "annotation %s incorrectly specified, parameter name does not refer to a pointer type", l.Text)
					continue outerLoop
				}

				structType, ok := ptrType.Elem().Underlying().(*types.Struct)
				if !ok {
					pc.pass.Reportf(l.Pos(), "annotation %s incorrectly specified, parameter name does not refer to a pointer to a struct", l.Text)
					continue outerLoop
				}

				for i := 0; i < structType.NumFields(); i++ {
					if structType.Field(i).Name() == fieldName {
						var fieldFacts lockFieldFacts
						pc.pass.ImportObjectFact(structType.Field(i), &fieldFacts)
						if !fieldFacts.IsMutex && !fieldFacts.IsRWMutex {
							pc.pass.Reportf(l.Pos(), "field %s of param %s is not a mutex or an rwmutex", paramName, structType.Field(i))
							continue outerLoop
						}
						funcFacts.GuardedBy[guardName] = functionGuard{ParameterNumber: paramNum, FieldNumber: i}
						found = true
						continue outerLoop
					}
				}
				if !found {
					pc.pass.Reportf(l.Pos(), "annotation refers to a non-existent field %s in %s", guardName, structType)
					continue outerLoop
				}
			}
			if !found {
				pc.pass.Reportf(l.Pos(), "annotation refers to a non-existent parameter %s", paramName)
			}
		}
	}

	if len(funcFacts.GuardedBy) == 0 {
		return
	}
	if ignore {
		pc.pass.Reportf(ignorePos, "//+checklocksignore cannot be specified with other annotations on the function")
	}
	funcObj, ok := pc.pass.TypesInfo.Defs[d.Name].(*types.Func)
	if !ok {
		panic(fmt.Sprintf("function type information missing for %+v", d))
	}
	log.Debugf("export fact for d: %+v, funcObj: %+v, funcFacts: %+v\n", d, funcObj, funcFacts)
	pc.pass.ExportObjectFact(funcObj, &funcFacts)
}

type mutexState struct {
	// lockedMutexes is used to track which mutexes in a given struct are
	// currently locked using the field number of the mutex as the key.
	lockedMutexes map[int]struct{}
}

// locksHeld tracks all currently held locks.
type locksHeld struct {
	locks map[ssa.Value]mutexState
}

// Same returns true if the locks held by other and l are the same.
func (l *locksHeld) Same(other *locksHeld) bool {
	return reflect.DeepEqual(l.locks, other.locks)
}

// Copy creates a copy of all the lock state held by l.
func (l *locksHeld) Copy() *locksHeld {
	out := &locksHeld{locks: make(map[ssa.Value]mutexState)}
	for ssaVal, mState := range l.locks {
		newLM := make(map[int]struct{})
		for k, v := range mState.lockedMutexes {
			newLM[k] = v
		}
		out.locks[ssaVal] = mutexState{lockedMutexes: newLM}
	}
	return out
}

func isAlias(first, second ssa.Value) bool {
	if first == second {
		return true
	}
	switch x := first.(type) {
	case *ssa.Field:
		if y, ok := second.(*ssa.Field); ok {
			return x.Field == y.Field && isAlias(x.X, y.X)
		}
	case *ssa.FieldAddr:
		if y, ok := second.(*ssa.FieldAddr); ok {
			return x.Field == y.Field && isAlias(x.X, y.X)
		}
	case *ssa.Index:
		if y, ok := second.(*ssa.Index); ok {
			return isAlias(x.Index, y.Index) && isAlias(x.X, y.X)
		}
	case *ssa.IndexAddr:
		if y, ok := second.(*ssa.IndexAddr); ok {
			return isAlias(x.Index, y.Index) && isAlias(x.X, y.X)
		}
	case *ssa.UnOp:
		if y, ok := second.(*ssa.UnOp); ok {
			return isAlias(x.X, y.X)
		}
	}
	return false
}

// checkBasicBlocks traverses the control flow graph starting at a set of given
// block and checks each instruction for allowed operations.
//
// funcFact are the exported facts for the enclosing function for these basic
// blocks.
func (pc *passContext) checkBasicBlocks(blocks []*ssa.BasicBlock, recoverBlock *ssa.BasicBlock, fn *ssa.Function, funcFact lockFunctionFacts) {
	if len(blocks) == 0 {
		return
	}

	// mutexes is used to track currently locked sync.Mutexes/sync.RWMutexes for a
	// given *struct identified by ssa.Value.
	seen := make(map[*ssa.BasicBlock]*locksHeld)
	var scan func(block *ssa.BasicBlock, parent *locksHeld)
	scan = func(block *ssa.BasicBlock, parent *locksHeld) {
		_, isExempted := pc.exemptions[block.Parent().Object()]
		if oldLocksHeld, ok := seen[block]; ok {
			if oldLocksHeld.Same(parent) {
				return
			}
			pc.maybeFail(block.Instrs[0].Pos(), isExempted, "failure entering a block %+v with different sets of lock held, oldLocks: %+v, parentLocks: %+v", block, oldLocksHeld, parent)
			return
		}
		seen[block] = parent
		var lh = parent.Copy()
		for _, inst := range block.Instrs {
			pc.checkInstruction(inst, isExempted, lh)
		}
		for _, b := range block.Succs {
			scan(b, lh)
		}
	}

	// Initialize lh with any preconditions that require locks to be held for the
	// method to be invoked.
	lh := &locksHeld{locks: make(map[ssa.Value]mutexState)}
	for _, fg := range funcFact.GuardedBy {
		// The first is the method object itself so we skip that when looking
		// for receiver/function parameters.
		log.Debugf("fn: %s, fn.Operands() == %+v", fn, fn.Operands(nil))
		r := fn.Params[fg.ParameterNumber]
		guardObj := findField(r, fg.FieldNumber)
		var fieldFacts lockFieldFacts
		pc.pass.ImportObjectFact(guardObj, &fieldFacts)
		if fieldFacts.IsMutex || fieldFacts.IsRWMutex {
			m, ok := lh.locks[r]
			if !ok {
				m = mutexState{lockedMutexes: make(map[int]struct{})}
				lh.locks[r] = m
			}
			m.lockedMutexes[fieldFacts.FieldNumber] = struct{}{}
		} else {
			panic(fmt.Sprintf("function: %+v has an invalid guard that is not a mutex: %+v", fn, guardObj))
		}
	}

	// Start scanning from the first basic block.
	scan(blocks[0], lh)

	// Validate that all blocks were touched.
	for _, b := range blocks {
		if _, ok := seen[b]; !ok && b != recoverBlock {
			panic(fmt.Sprintf("block %+v was not visited during checkBasicBlocks", b))
		}
	}
}

func (pc *passContext) checkInstruction(inst ssa.Instruction, isExempted bool, lh *locksHeld) {
	log.Debugf("checking instruction: %s, isExempted: %t", inst, isExempted)
	switch x := inst.(type) {
	case *ssa.Field:
		pc.checkFieldAccess(inst, x.X, x.Field, isExempted, lh)
	case *ssa.FieldAddr:
		pc.checkFieldAccess(inst, x.X, x.Field, isExempted, lh)
	case *ssa.Call:
		pc.checkFunctionCall(x, isExempted, lh)
	}
}

func findField(v ssa.Value, field int) types.Object {
	structType, ok := v.Type().Underlying().(*types.Struct)
	if !ok {
		ptrType, ok := v.Type().Underlying().(*types.Pointer)
		if !ok {
			return nil
		}
		structType = ptrType.Elem().Underlying().(*types.Struct)
	}
	return structType.Field(field)
}

func (pc *passContext) maybeFail(pos token.Pos, isExempted bool, fmtStr string, args ...interface{}) {
	posKey := toPositionKey(pc.pass.Fset.Position(pos))
	log.Debugf("maybeFail: pos: %d, positionKey: %s", pos, posKey)
	if fData, ok := pc.failures[posKey]; ok {
		fData.count--
		if fData.count == 0 {
			delete(pc.failures, posKey)
		}
		return
	}
	if !isExempted {
		pc.pass.Reportf(pos, fmt.Sprintf(fmtStr, args...))
	}
}

func (pc *passContext) checkFieldAccess(inst ssa.Instruction, structObj ssa.Value, field int, isExempted bool, lh *locksHeld) {
	var fieldFacts lockFieldFacts
	fieldObj := findField(structObj, field)
	pc.pass.ImportObjectFact(fieldObj, &fieldFacts)
	log.Debugf("fieldObj: %s, fieldFacts: %+v", fieldObj, fieldFacts)
	for _, guardFieldNumber := range fieldFacts.GuardedBy {
		guardObj := findField(structObj, guardFieldNumber)
		var guardfieldFacts lockFieldFacts
		pc.pass.ImportObjectFact(guardObj, &guardfieldFacts)
		log.Debugf("guardObj: %s, guardFieldFacts: %+v", guardObj, guardfieldFacts)
		if guardfieldFacts.IsMutex || guardfieldFacts.IsRWMutex {
			log.Debugf("guard is a mutex")
			m, ok := lh.locks[structObj]
			if !ok {
				pc.maybeFail(inst.Pos(), isExempted, "invalid field access, %s must be locked when accessing %s", guardObj.Name(), fieldObj.Name())
				continue
			}
			if _, ok := m.lockedMutexes[guardfieldFacts.FieldNumber]; !ok {
				pc.maybeFail(inst.Pos(), isExempted, "invalid field access, %s must be locked when accessing %s", guardObj.Name(), fieldObj.Name())
			}
		} else {
			panic("incorrect guard that is not a mutex or an RWMutex")
		}
	}
}

func (pc *passContext) checkFunctionCall(call *ssa.Call, isExempted bool, lh *locksHeld) {
	// See: https://godoc.org/golang.org/x/tools/go/ssa#CallCommon
	//
	// 1. "call" mode: when Method is nil (!IsInvoke), a CallCommon represents an ordinary
	//  function call of the value in Value, which may be a *Builtin, a *Function or any
	//  other value of kind 'func'.
	//
	// 	Value may be one of:
	// (a) a *Function, indicating a statically dispatched call
	// to a package-level function, an anonymous function, or
	// a method of a named type.
	//
	// (b) a *MakeClosure, indicating an immediately applied
	// function literal with free variables.
	//
	// (c) a *Builtin, indicating a statically dispatched call
	// to a built-in function.
	//
	// (d) any other value, indicating a dynamically dispatched
	//     function call.
	fn, ok := call.Common().Value.(*ssa.Function)
	if !ok {
		return
	}
	if fn.Object() == nil {
		return
	}

	// Check if the function should be called with any locks held.
	var funcFact lockFunctionFacts
	pc.pass.ImportObjectFact(fn.Object(), &funcFact)
	if len(funcFact.GuardedBy) > 0 {
		for _, fg := range funcFact.GuardedBy {
			// The first is the method object itself so we skip that when looking
			// for receiver/function parameters.
			r := (*call.Value().Operands(nil)[fg.ParameterNumber+1])
			guardObj := findField(r, fg.FieldNumber)
			if guardObj == nil {
				continue
			}
			var fieldFacts lockFieldFacts
			pc.pass.ImportObjectFact(guardObj, &fieldFacts)
			if fieldFacts.IsMutex || fieldFacts.IsRWMutex {
				heldMutexes, ok := lh.locks[r]
				if !ok {
					log.Debugf("fn: %s, funcFact: %+v", fn, funcFact)
					pc.maybeFail(call.Pos(), isExempted, "invalid function call %s must be held", guardObj.Name())
					continue
				}
				if _, ok := heldMutexes.lockedMutexes[fg.FieldNumber]; !ok {
					log.Debugf("fn: %s, funcFact: %+v", fn, funcFact)
					pc.maybeFail(call.Pos(), isExempted, "invalid function call %s must be held", guardObj.Name())
				}
			} else {
				panic(fmt.Sprintf("function: %+v has an invalid guard that is not a mutex: %+v", fn, guardObj))
			}
		}
	}

	// Check if it's a method dispatch for something in the sync package.
	// See: https://godoc.org/golang.org/x/tools/go/ssa#Function
	if fn.Package() != nil && fn.Package().Pkg.Name() == "sync" && fn.Signature.Recv() != nil {
		r, ok := call.Common().Args[0].(*ssa.FieldAddr)
		if !ok {
			return
		}
		guardObj := findField(r.X, r.Field)
		var fieldFacts lockFieldFacts
		pc.pass.ImportObjectFact(guardObj, &fieldFacts)
		if fieldFacts.IsMutex || fieldFacts.IsRWMutex {
			switch fn.Name() {
			case "Lock", "RLock":
				obj := r.X
				m := mutexState{lockedMutexes: make(map[int]struct{})}
				for k, v := range lh.locks {
					if isAlias(r.X, k) {
						obj = k
						m = v
					}
				}
				if _, ok := m.lockedMutexes[r.Field]; ok {
					// Double locking a mutex that is already locked.
					pc.maybeFail(call.Pos(), isExempted, "trying to a lock %s when already locked", guardObj.Name())
					return
				}
				m.lockedMutexes[r.Field] = struct{}{}
				lh.locks[obj] = m
			case "Unlock", "RUnlock":
				// Find the associated locker object.
				var (
					obj ssa.Value
					m   mutexState
				)
				for k, v := range lh.locks {
					if isAlias(r.X, k) {
						obj = k
						m = v
						break
					}
				}
				if _, ok := m.lockedMutexes[r.Field]; !ok {
					pc.maybeFail(call.Pos(), isExempted, "trying to unlock a mutex %s that is already unlocked", guardObj.Name())
					return
				}
				delete(m.lockedMutexes, r.Field)
				if len(m.lockedMutexes) == 0 {
					delete(lh.locks, obj)
				}
			case "RLocker", "DowngradeLock", "TryLock", "TryRLock":
				// we explicitly ignore this for now.
			default:
				panic(fmt.Sprintf("unexpected mutex/rwmutex method invoked: %s", fn.Name()))
			}
		}
	}
}

func run(pass *analysis.Pass) (interface{}, error) {
	pc := &passContext{
		pass:       pass,
		exemptions: make(map[types.Object]struct{}),
		failures:   make(map[positionKey]*failData),
	}

	// Find all line failure annotations.
	for _, f := range pass.Files {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, checkLocksFail) {
					cnt := 1
					if strings.Contains(c.Text, checkLocksFail+":") {
						parts := strings.SplitAfter(c.Text, checkLocksFail+":")
						parsedCount, err := strconv.Atoi(parts[1])
						if err != nil {
							pc.pass.Reportf(c.Pos(), "invalid checklocks annotation : %s", err)
							continue
						}
						cnt = parsedCount
					}
					position := toPositionKey(pass.Fset.Position(c.Pos()))
					pc.failures[position] = &failData{pos: c.Pos(), count: cnt}
				}
			}
		}
	}

	// Find all struct declarations and export any relevant facts.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			// A GenDecl node (generic declaration node) represents an import,
			// constant, type or variable declaration.  We only care about struct
			// declarations so skip any declaration that doesn't declare a new type.
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
				pc.findAndExportStructFacts(ss, structType)
			}
		}
	}

	// Find all method calls and export any relevant facts.
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			// Ignore any non function declarations and any functions that do not have
			// any comments.
			if !ok || d.Doc == nil {
				continue
			}
			pc.findAndExportFuncFacts(d)
		}
	}

	// log all known facts and all failures if debug logging is enabled.
	allFacts := pass.AllObjectFacts()
	for i := range allFacts {
		log.Debugf("fact.object: %+v, fact.Fact: %+v", allFacts[i].Object, allFacts[i].Fact)
	}
	log.Debugf("all expected failures: %+v", pc.failures)

	// Scan all code looking for invalid accesses.
	state := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	for _, fn := range state.SrcFuncs {
		var funcFact lockFunctionFacts
		// Anonymous(closures) functions do not have an object() but do show up in
		// the SSA.
		if obj := fn.Object(); obj != nil {
			pc.pass.ImportObjectFact(fn.Object(), &funcFact)
		}

		log.Debugf("checking function: %s", fn)
		var b bytes.Buffer
		ssa.WriteFunction(&b, fn)
		log.Debugf("function SSA: %s", b.String())
		if fn.Recover != nil {
			pc.checkBasicBlocks([]*ssa.BasicBlock{fn.Recover}, nil, fn, funcFact)
		}
		pc.checkBasicBlocks(fn.Blocks, fn.Recover, fn, funcFact)
	}

	// Scan for remaining failures we expect.
	for _, failure := range pc.failures {
		// We are missing expect failures, report as much as possible.
		pass.Reportf(failure.pos, "expected %d failures", failure.count)
	}

	return nil, nil
}
