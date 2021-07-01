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

package checklocks

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// atomicAlignment is saved per type.
//
// This represents the alignment required for the type, which may
// be implied and imposed by other types within the aggregate type.
type atomicAlignment int

// AFact implements analysis.Fact.AFact.
func (*atomicAlignment) AFact() {}

// atomicDisposition is saved per field.
//
// This represents how the field must be accessed. It must either
// be non-atomic (default), atomic or ignored.
type atomicDisposition int

const (
	atomicDisallow atomicDisposition = iota
	atomicIgnore
	atomicRequired
)

// fieldList is a simple list of fields, used in two types below.
//
// Note that the integers in this list refer to one of two things:
// - A positive integer refers to a field index in a struct.
// - A negative integer refers to a field index in a struct, where
//   that field is a pointer and must be subsequently resolved.
type fieldList []int

// resolvedValue is an ssa.Value with additional fields.
//
// This can be resolved to a string as part of a lock state.
type resolvedValue struct {
	value     ssa.Value
	valid     bool
	fieldList []int
}

// findExtract finds a relevant extract. This must exist within the referrers
// to the call object. If this doesn't then the object which is locked is never
// consumed, and we should consider this a bug.
func findExtract(v ssa.Value, index int) (ssa.Value, bool) {
	if refs := v.Referrers(); refs != nil {
		for _, inst := range *refs {
			if x, ok := inst.(*ssa.Extract); ok && x.Tuple == v && x.Index == index {
				return inst.(ssa.Value), true
			}
		}
	}
	return nil, false
}

// resolve resolves the given field list.
func (fl fieldList) resolve(v ssa.Value) (rv resolvedValue) {
	return resolvedValue{
		value:     v,
		fieldList: fl,
		valid:     true,
	}
}

// valueAsString returns a string representing this value.
//
// This must align with how the string is generated in valueAsString.
func (rv resolvedValue) valueAsString(ls *lockState) string {
	typ := rv.value.Type()
	s := ls.valueAsString(rv.value)
	for i, fieldNumber := range rv.fieldList {
		switch {
		case fieldNumber > 0:
			field, ok := findField(typ, fieldNumber-1)
			if !ok {
				// This can't be resolved, return for debugging.
				return fmt.Sprintf("{%s+%v}", s, rv.fieldList[i:])
			}
			s = fmt.Sprintf("&(%s.%s)", s, field.Name())
			typ = field.Type()
		case fieldNumber < 1:
			field, ok := findField(typ, (-fieldNumber)-1)
			if !ok {
				// See above.
				return fmt.Sprintf("{%s+%v}", s, rv.fieldList[i:])
			}
			s = fmt.Sprintf("*(&(%s.%s))", s, field.Name())
			typ = field.Type()
		}
	}
	return s
}

// lockFieldFacts apply on every struct field.
type lockFieldFacts struct {
	// IsMutex is true if the field is of type sync.Mutex.
	IsMutex bool

	// IsRWMutex is true if the field is of type sync.RWMutex.
	IsRWMutex bool

	// IsPointer indicates if the field is a pointer.
	IsPointer bool

	// FieldNumber is the number of this field in the struct.
	FieldNumber int
}

// AFact implements analysis.Fact.AFact.
func (*lockFieldFacts) AFact() {}

// lockGuardFacts contains guard information.
type lockGuardFacts struct {
	// GuardedBy is the set of locks that are guarding this field. The key
	// is the original annotation value, and the field list is the object
	// traversal path.
	GuardedBy map[string]fieldList

	// AtomicDisposition is the disposition for this field. Note that this
	// can affect the interpretation of the GuardedBy field above, see the
	// relevant comment.
	AtomicDisposition atomicDisposition
}

// AFact implements analysis.Fact.AFact.
func (*lockGuardFacts) AFact() {}

// functionGuard is used by lockFunctionFacts, below.
type functionGuard struct {
	// ParameterNumber is the index of the object that contains the
	// guarding mutex. From this parameter, a walk is performed
	// subsequently using the resolve method.
	//
	// Note that is ParameterNumber is beyond the size of parameters, then
	// it may return to a return value. This applies only for the Acquires
	// relation below.
	ParameterNumber int

	// NeedsExtract is used in the case of a return value, and indicates
	// that the field must be extracted from a tuple.
	NeedsExtract bool

	// FieldList is the traversal path to the object.
	FieldList fieldList
}

// resolveReturn resolves a return value.
//
// Precondition: rv is either an ssa.Value, or an *ssa.Return.
func (fg *functionGuard) resolveReturn(rv interface{}, args int) resolvedValue {
	if rv == nil {
		// For defers and other objects, this may be nil. This is
		// handled in state.go in the actual lock checking logic.
		return resolvedValue{
			value: nil,
			valid: false,
		}
	}
	index := fg.ParameterNumber - args
	// If this is a *ssa.Return object, i.e. we are analyzing the function
	// and not the call site, then we can just pull the result directly.
	if r, ok := rv.(*ssa.Return); ok {
		return fg.FieldList.resolve(r.Results[index])
	}
	if fg.NeedsExtract {
		// Resolve on the extracted field, this is necessary if the
		// type here is not an explicit return. Note that rv must be an
		// ssa.Value, since it is not an *ssa.Return.
		v, ok := findExtract(rv.(ssa.Value), index)
		if !ok {
			return resolvedValue{
				value: v,
				valid: false,
			}
		}
		return fg.FieldList.resolve(v)
	}
	if index != 0 {
		// This should not happen, NeedsExtract should always be set.
		panic("NeedsExtract is false, but return value index is non-zero")
	}
	// Resolve on the single return.
	return fg.FieldList.resolve(rv.(ssa.Value))
}

// resolveStatic returns an ssa.Value representing the given field.
//
// Precondition: per resolveReturn.
func (fg *functionGuard) resolveStatic(fn *ssa.Function, rv interface{}) resolvedValue {
	if fg.ParameterNumber >= len(fn.Params) {
		return fg.resolveReturn(rv, len(fn.Params))
	}
	return fg.FieldList.resolve(fn.Params[fg.ParameterNumber])
}

// resolveCall returns an ssa.Value representing the given field.
func (fg *functionGuard) resolveCall(args []ssa.Value, rv ssa.Value) resolvedValue {
	if fg.ParameterNumber >= len(args) {
		return fg.resolveReturn(rv, len(args))
	}
	return fg.FieldList.resolve(args[fg.ParameterNumber])
}

// lockFunctionFacts apply on every method.
type lockFunctionFacts struct {
	// HeldOnEntry tracks the names and number of parameter (including receiver)
	// lockFuncfields that guard calls to this function.
	//
	// The key is the name specified in the checklocks annotation. e.g given
	// the following code:
	//
	// ```
	// type A struct {
	//	mu sync.Mutex
	//	a int
	// }
	//
	// // +checklocks:a.mu
	// func xyz(a *A) {..}
	// ```
	//
	// '`+checklocks:a.mu' will result in an entry in this map as shown below.
	// HeldOnEntry: {"a.mu" => {ParameterNumber: 0, FieldNumbers: {0}}
	//
	// Unlikely lockFieldFacts, there is no atomic interpretation.
	HeldOnEntry map[string]functionGuard

	// HeldOnExit tracks the locks that are expected to be held on exit.
	HeldOnExit map[string]functionGuard

	// Ignore means this function has local analysis ignores.
	//
	// This is not used outside the local package.
	Ignore bool
}

// AFact implements analysis.Fact.AFact.
func (*lockFunctionFacts) AFact() {}

// checkGuard validates the guardName.
func (lff *lockFunctionFacts) checkGuard(pc *passContext, d *ast.FuncDecl, guardName string, allowReturn bool) (functionGuard, bool) {
	if _, ok := lff.HeldOnEntry[guardName]; ok {
		pc.maybeFail(d.Pos(), "annotation %s specified more than once, already required", guardName)
		return functionGuard{}, false
	}
	if _, ok := lff.HeldOnExit[guardName]; ok {
		pc.maybeFail(d.Pos(), "annotation %s specified more than once, already acquired", guardName)
		return functionGuard{}, false
	}
	fg, ok := pc.findFunctionGuard(d, guardName, allowReturn)
	return fg, ok
}

// addGuardedBy adds a field to both HeldOnEntry and HeldOnExit.
func (lff *lockFunctionFacts) addGuardedBy(pc *passContext, d *ast.FuncDecl, guardName string) {
	if fg, ok := lff.checkGuard(pc, d, guardName, false /* allowReturn */); ok {
		if lff.HeldOnEntry == nil {
			lff.HeldOnEntry = make(map[string]functionGuard)
		}
		if lff.HeldOnExit == nil {
			lff.HeldOnExit = make(map[string]functionGuard)
		}
		lff.HeldOnEntry[guardName] = fg
		lff.HeldOnExit[guardName] = fg
	}
}

// addAcquires adds a field to HeldOnExit.
func (lff *lockFunctionFacts) addAcquires(pc *passContext, d *ast.FuncDecl, guardName string) {
	if fg, ok := lff.checkGuard(pc, d, guardName, true /* allowReturn */); ok {
		if lff.HeldOnExit == nil {
			lff.HeldOnExit = make(map[string]functionGuard)
		}
		lff.HeldOnExit[guardName] = fg
	}
}

// addReleases adds a field to HeldOnEntry.
func (lff *lockFunctionFacts) addReleases(pc *passContext, d *ast.FuncDecl, guardName string) {
	if fg, ok := lff.checkGuard(pc, d, guardName, false /* allowReturn */); ok {
		if lff.HeldOnEntry == nil {
			lff.HeldOnEntry = make(map[string]functionGuard)
		}
		lff.HeldOnEntry[guardName] = fg
	}
}

// fieldListFor returns the fieldList for the given object.
func (pc *passContext) fieldListFor(pos token.Pos, fieldObj types.Object, index int, fieldName string, checkMutex bool) (int, bool) {
	var lff lockFieldFacts
	if !pc.pass.ImportObjectFact(fieldObj, &lff) {
		// This should not happen: we export facts for all fields.
		panic(fmt.Sprintf("no lockFieldFacts available for field %s", fieldName))
	}
	// Check that it is indeed a mutex.
	if checkMutex && !lff.IsMutex && !lff.IsRWMutex {
		pc.maybeFail(pos, "field %s is not a mutex or an rwmutex", fieldName)
		return 0, false
	}
	// Return the resolution path.
	if lff.IsPointer {
		return -(index + 1), true
	}
	return (index + 1), true
}

// resolveOneField resolves a field in a single struct.
func (pc *passContext) resolveOneField(pos token.Pos, structType *types.Struct, fieldName string, checkMutex bool) (fl fieldList, fieldObj types.Object, ok bool) {
	// Scan to match the next field.
	for i := 0; i < structType.NumFields(); i++ {
		fieldObj := structType.Field(i)
		if fieldObj.Name() != fieldName {
			continue
		}
		flOne, ok := pc.fieldListFor(pos, fieldObj, i, fieldName, checkMutex)
		if !ok {
			return nil, nil, false
		}
		fl = append(fl, flOne)
		return fl, fieldObj, true
	}
	// Is this an embed?
	for i := 0; i < structType.NumFields(); i++ {
		fieldObj := structType.Field(i)
		if !fieldObj.Embedded() {
			continue
		}
		// Is this an embedded struct?
		structType, ok := resolveStruct(fieldObj.Type())
		if !ok {
			continue
		}
		// Need to check that there is a resolution path. If there is
		// no resolution path that's not a failure: we just continue
		// scanning the next embed to find a match.
		flEmbed, okEmbed := pc.fieldListFor(pos, fieldObj, i, fieldName, false)
		flCont, fieldObjCont, okCont := pc.resolveOneField(pos, structType, fieldName, checkMutex)
		if okEmbed && okCont {
			fl = append(fl, flEmbed)
			fl = append(fl, flCont...)
			return fl, fieldObjCont, true
		}
	}
	pc.maybeFail(pos, "field %s does not exist", fieldName)
	return nil, nil, false
}

// resolveField resolves a set of fields given a string, such a 'a.b.c'.
//
// Note that this checks that the final element is a mutex of some kind, and
// will fail appropriately.
func (pc *passContext) resolveField(pos token.Pos, structType *types.Struct, parts []string) (fl fieldList, ok bool) {
	for partNumber, fieldName := range parts {
		flOne, fieldObj, ok := pc.resolveOneField(pos, structType, fieldName, partNumber >= len(parts)-1 /* checkMutex */)
		if !ok {
			// Error already reported.
			return nil, false
		}
		fl = append(fl, flOne...)
		if partNumber < len(parts)-1 {
			// Traverse to the next type.
			structType, ok = resolveStruct(fieldObj.Type())
			if !ok {
				pc.maybeFail(pos, "invalid intermediate field %s", fieldName)
				return fl, false
			}
		}
	}
	return fl, true
}

var (
	mutexRE   = regexp.MustCompile("((.*/)|^)sync.(CrossGoroutineMutex|Mutex)")
	rwMutexRE = regexp.MustCompile("((.*/)|^)sync.(CrossGoroutineRWMutex|RWMutex)")
)

// exportLockFieldFacts finds all struct fields that are mutexes, and ensures
// that they are annotated approperly.
//
// This information is consumed subsequently by exportLockGuardFacts, and this
// function must be called first on all structures.
func (pc *passContext) exportLockFieldFacts(ts *ast.TypeSpec, ss *ast.StructType) {
	structType := pc.pass.TypesInfo.TypeOf(ts.Name).Underlying().(*types.Struct)
	for i := range ss.Fields.List {
		lff := &lockFieldFacts{
			FieldNumber: i,
		}
		// We use HasSuffix below because fieldType can be fully
		// qualified with the package name eg for the gvisor sync
		// package mutex fields have the type:
		//	"<package path>/sync/sync.Mutex"
		fieldObj := structType.Field(i)
		s := fieldObj.Type().String()
		switch {
		case mutexRE.MatchString(s):
			lff.IsMutex = true
		case rwMutexRE.MatchString(s):
			lff.IsRWMutex = true
		}
		// Save whether this is a pointer.
		_, lff.IsPointer = fieldObj.Type().Underlying().(*types.Pointer)
		// We must always export the lockFieldFacts, since traversal
		// can take place along any object in the struct.
		pc.pass.ExportObjectFact(fieldObj, lff)
	}
}

// exportLockGuardFacts finds all relevant guard information for structures.
//
// This function requires exportLockFieldFacts be called first on all
// structures.
func (pc *passContext) exportLockGuardFacts(ts *ast.TypeSpec, ss *ast.StructType) {
	structType := pc.pass.TypesInfo.TypeOf(ts.Name).Underlying().(*types.Struct)
	for i, field := range ss.Fields.List {
		if field.Doc == nil {
			continue
		}
		var (
			lff lockFieldFacts
			lgf lockGuardFacts
		)
		pc.pass.ImportObjectFact(structType.Field(i), &lff)
		fieldObj := structType.Field(i)
		for _, l := range field.Doc.List {
			pc.extractAnnotations(l.Text, map[string]func(string){
				checkAtomicAnnotation: func(string) {
					switch lgf.AtomicDisposition {
					case atomicRequired:
						pc.maybeFail(fieldObj.Pos(), "annotation is redundant, already atomic required")
					case atomicIgnore:
						pc.maybeFail(fieldObj.Pos(), "annotation is contradictory, already atomic ignored")
					}
					lgf.AtomicDisposition = atomicRequired
				},
				checkLocksIgnore: func(string) {
					switch lgf.AtomicDisposition {
					case atomicIgnore:
						pc.maybeFail(fieldObj.Pos(), "annotation is redundant, already atomic ignored")
					case atomicRequired:
						pc.maybeFail(fieldObj.Pos(), "annotation is contradictory, already atomic required")
					}
					lgf.AtomicDisposition = atomicIgnore
				},
				checkLocksAnnotation: func(guardName string) {
					// Check for a duplicate annotation.
					if _, ok := lgf.GuardedBy[guardName]; ok {
						pc.maybeFail(fieldObj.Pos(), "annotation %s specified more than once", guardName)
						return
					}
					fl, ok := pc.resolveField(fieldObj.Pos(), structType, strings.Split(guardName, "."))
					if ok {
						// If we successfully resolved
						// the field, then save it.
						if lgf.GuardedBy == nil {
							lgf.GuardedBy = make(map[string]fieldList)
						}
						lgf.GuardedBy[guardName] = fl
					}
				},
			})
		}
		// Save only if there is something meaningful.
		if len(lgf.GuardedBy) > 0 || lgf.AtomicDisposition != atomicDisallow {
			pc.pass.ExportObjectFact(structType.Field(i), &lgf)
		}
	}
}

// countFields gives an accurate field count, according for unnamed arguments
// and return values and the compact identifier format.
func countFields(fl []*ast.Field) (count int) {
	for _, field := range fl {
		if len(field.Names) == 0 {
			count++
			continue
		}
		count += len(field.Names)
	}
	return
}

// matchFieldList attempts to match the given field.
func (pc *passContext) matchFieldList(pos token.Pos, fl []*ast.Field, guardName string) (functionGuard, bool) {
	parts := strings.Split(guardName, ".")
	parameterName := parts[0]
	parameterNumber := 0
	for _, field := range fl {
		// See countFields, above.
		if len(field.Names) == 0 {
			parameterNumber++
			continue
		}
		for _, name := range field.Names {
			if name.Name != parameterName {
				parameterNumber++
				continue
			}
			ptrType, ok := pc.pass.TypesInfo.TypeOf(field.Type).Underlying().(*types.Pointer)
			if !ok {
				// Since mutexes cannot be copied we only care
				// about parameters that are pointer types when
				// checking for guards.
				pc.maybeFail(pos, "parameter name %s does not refer to a pointer type", parameterName)
				return functionGuard{}, false
			}
			structType, ok := ptrType.Elem().Underlying().(*types.Struct)
			if !ok {
				// Fields can only be in named structures.
				pc.maybeFail(pos, "parameter name %s does not refer to a pointer to a struct", parameterName)
				return functionGuard{}, false
			}
			fg := functionGuard{
				ParameterNumber: parameterNumber,
			}
			fl, ok := pc.resolveField(pos, structType, parts[1:])
			fg.FieldList = fl
			return fg, ok // If ok is false, already failed.
		}
	}
	return functionGuard{}, false
}

// findFunctionGuard identifies the parameter number and field number for a
// particular string of the 'a.b'.
//
// This function will report any errors directly.
func (pc *passContext) findFunctionGuard(d *ast.FuncDecl, guardName string, allowReturn bool) (functionGuard, bool) {
	var (
		parameterList []*ast.Field
		returnList    []*ast.Field
	)
	if d.Recv != nil {
		parameterList = append(parameterList, d.Recv.List...)
	}
	if d.Type.Params != nil {
		parameterList = append(parameterList, d.Type.Params.List...)
	}
	if fg, ok := pc.matchFieldList(d.Pos(), parameterList, guardName); ok {
		return fg, ok
	}
	if allowReturn {
		if d.Type.Results != nil {
			returnList = append(returnList, d.Type.Results.List...)
		}
		if fg, ok := pc.matchFieldList(d.Pos(), returnList, guardName); ok {
			// Fix this up to apply to the return value, as noted
			// in fg.ParameterNumber. For the ssa analysis, we must
			// record whether this has multiple results, since
			// *ssa.Call indicates: "The Call instruction yields
			// the function result if there is exactly one.
			// Otherwise it returns a tuple, the components of
			// which are accessed via Extract."
			fg.ParameterNumber += countFields(parameterList)
			fg.NeedsExtract = countFields(returnList) > 1
			return fg, ok
		}
	}
	// We never saw a matching parameter.
	pc.maybeFail(d.Pos(), "annotation %s does not have a matching parameter", guardName)
	return functionGuard{}, false
}

// exportFunctionFacts exports relevant function findings.
func (pc *passContext) exportFunctionFacts(d *ast.FuncDecl) {
	if d.Doc == nil || d.Doc.List == nil {
		return
	}
	var lff lockFunctionFacts
	for _, l := range d.Doc.List {
		pc.extractAnnotations(l.Text, map[string]func(string){
			checkLocksIgnore: func(string) {
				// Note that this applies to all atomic
				// analysis as well. There is no provided way
				// to selectively ignore only lock analysis or
				// atomic analysis, as we expect this use to be
				// extremely rare.
				lff.Ignore = true
			},
			checkLocksAnnotation: func(guardName string) { lff.addGuardedBy(pc, d, guardName) },
			checkLocksAcquires:   func(guardName string) { lff.addAcquires(pc, d, guardName) },
			checkLocksReleases:   func(guardName string) { lff.addReleases(pc, d, guardName) },
		})
	}

	// Export the function facts if there is anything to save.
	if lff.Ignore || len(lff.HeldOnEntry) > 0 || len(lff.HeldOnExit) > 0 {
		funcObj := pc.pass.TypesInfo.Defs[d.Name].(*types.Func)
		pc.pass.ExportObjectFact(funcObj, &lff)
	}
}
