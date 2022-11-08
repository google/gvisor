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
	"encoding/gob"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis/passes/buildssa"
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

// fieldEntry is a single field type.
type fieldEntry interface {
	// synthesize produces a string that is compatible with valueAndObject,
	// along with the same object that should be produced in that case.
	//
	// Note that it is called synthesize because this is produced only the
	// type information, and not with any ssa.Value objects.
	synthesize(s string, typ types.Type) (string, types.Object)
}

// fieldStruct is a non-pointer struct element.
type fieldStruct int

// synthesize implements fieldEntry.synthesize.
func (f fieldStruct) synthesize(s string, typ types.Type) (string, types.Object) {
	field, ok := findField(typ, int(f))
	if !ok {
		// Should not happen as long as fieldList construction is correct.
		panic(fmt.Sprintf("unable to resolve field %d in %s", int(f), typ.String()))
	}
	return fmt.Sprintf("&(%s.%s)", s, field.Name()), field
}

// fieldStructPtr is a pointer struct element.
type fieldStructPtr int

// synthesize implements fieldEntry.synthesize.
func (f fieldStructPtr) synthesize(s string, typ types.Type) (string, types.Object) {
	field, ok := findField(typ, int(f))
	if !ok {
		// See above, this should not happen.
		panic(fmt.Sprintf("unable to resolve ptr field %d in %s", int(f), typ.String()))
	}
	return fmt.Sprintf("*(&(%s.%s))", s, field.Name()), field
}

// fieldList is a simple list of fields, used in two types below.
type fieldList []fieldEntry

// resolvedValue is an ssa.Value with additional fields.
//
// This can be resolved to a string as part of a lock state.
type resolvedValue struct {
	value     ssa.Value
	fieldList fieldList
}

// makeResolvedValue makes a new resolvedValue.
func makeResolvedValue(v ssa.Value, fl fieldList) resolvedValue {
	return resolvedValue{
		value:     v,
		fieldList: fl,
	}
}

// valid indicates whether this is a valid resolvedValue.
func (rv *resolvedValue) valid() bool {
	return rv.value != nil
}

// valueAndObject returns a string and object.
//
// This uses the lockState valueAndObject in order to produce a string and
// object for the base ssa.Value, then synthesizes a string representation
// based on the fieldList.
func (rv *resolvedValue) valueAndObject(ls *lockState) (string, types.Object) {
	// N.B. obj.Type() and typ should be equal, but a check is omitted
	// since, 1) we automatically chase through pointers during field
	// resolution, and 2) obj may be nil if there is no source object.
	s, obj := ls.valueAndObject(rv.value)
	typ := rv.value.Type()
	for _, entry := range rv.fieldList {
		s, obj = entry.synthesize(s, typ)
		typ = obj.Type()
	}
	return s, obj
}

// fieldGuardResolver details a guard for a field.
type fieldGuardResolver interface {
	// resolveField is used to resolve a guard during a field access. The
	// parent structure is available, as well as the current lock state.
	resolveField(pc *passContext, ls *lockState, parent ssa.Value) resolvedValue
}

// functionGuardResolver details a guard for a function.
type functionGuardResolver interface {
	// resolveStatic is used to resolve a guard during static analysis,
	// e.g. based on static annotations applied to a method. The function's
	// ssa object is available, as well as the return value.
	resolveStatic(pc *passContext, ls *lockState, fn *ssa.Function, rv any) resolvedValue

	// resolveCall is used to resolve a guard during a call. The ssa
	// return value is available from the instruction context where the
	// call occurs, but the target's ssa representation is not available.
	resolveCall(pc *passContext, ls *lockState, args []ssa.Value, rv ssa.Value) resolvedValue
}

// lockGuardFacts contains guard information.
type lockGuardFacts struct {
	// GuardedBy is the set of locks that are guarding this field. The key
	// is the original annotation value, and the field list is the object
	// traversal path.
	GuardedBy map[string]fieldGuardResolver

	// AtomicDisposition is the disposition for this field. Note that this
	// can affect the interpretation of the GuardedBy field above, see the
	// relevant comment.
	AtomicDisposition atomicDisposition
}

// AFact implements analysis.Fact.AFact.
func (*lockGuardFacts) AFact() {}

// globalGuard is a global value.
type globalGuard struct {
	// ObjectName indicates the object from which resolution should occur.
	ObjectName string

	// PackageName is the package where the object lives.
	PackageName string

	// FieldList is the traversal path from object.
	FieldList fieldList
}

// ssaPackager returns the ssa package.
type ssaPackager interface {
	Package() *ssa.Package
}

// resolveCommon implements resolution for all cases.
func (g *globalGuard) resolveCommon(pc *passContext, ls *lockState) resolvedValue {
	state := pc.pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	pkg := state.Pkg
	if g.PackageName != "" && g.PackageName != state.Pkg.Pkg.Path() {
		pkg = state.Pkg.Prog.ImportedPackage(g.PackageName)
	}
	v := pkg.Members[g.ObjectName].(ssa.Value)
	return makeResolvedValue(v, g.FieldList)
}

// resolveStatic implements functionGuardResolver.resolveStatic.
func (g *globalGuard) resolveStatic(pc *passContext, ls *lockState, _ *ssa.Function, v any) resolvedValue {
	return g.resolveCommon(pc, ls)
}

// resolveCall implements functionGuardResolver.resolveCall.
func (g *globalGuard) resolveCall(pc *passContext, ls *lockState, _ []ssa.Value, v ssa.Value) resolvedValue {
	return g.resolveCommon(pc, ls)
}

// resolveField implements fieldGuardResolver.resolveField.
func (g *globalGuard) resolveField(pc *passContext, ls *lockState, parent ssa.Value) resolvedValue {
	return g.resolveCommon(pc, ls)
}

// fieldGuard is a field-based guard.
type fieldGuard struct {
	// FieldList is the traversal path from the parent.
	FieldList fieldList
}

// resolveField implements fieldGuardResolver.resolveField.
func (f *fieldGuard) resolveField(_ *passContext, _ *lockState, parent ssa.Value) resolvedValue {
	return makeResolvedValue(parent, f.FieldList)
}

// parameterGuard is a parameter-based guard.
type parameterGuard struct {
	// Index is the parameter index of the object that contains the
	// guarding mutex.
	Index int

	// fieldList is the traversal path from the parameter.
	FieldList fieldList
}

// resolveStatic implements functionGuardResolver.resolveStatic.
func (p *parameterGuard) resolveStatic(_ *passContext, _ *lockState, fn *ssa.Function, _ any) resolvedValue {
	return makeResolvedValue(fn.Params[p.Index], p.FieldList)
}

// resolveCall implements functionGuardResolver.resolveCall.
func (p *parameterGuard) resolveCall(_ *passContext, _ *lockState, args []ssa.Value, _ ssa.Value) resolvedValue {
	return makeResolvedValue(args[p.Index], p.FieldList)
}

// returnGuard is a return-based guard.
type returnGuard struct {
	// Index is the index of the return value.
	Index int

	// NeedsExtract is used in the case of a return value, and indicates
	// that the field must be extracted from a tuple.
	NeedsExtract bool

	// FieldList is the traversal path from the return value.
	FieldList fieldList
}

// resolveCommon implements resolution for both cases.
func (r *returnGuard) resolveCommon(rv any) resolvedValue {
	if rv == nil {
		// For defers and other objects, this may be nil. This is
		// handled in state.go in the actual lock checking logic. This
		// means that there is no resolvedValue available.
		return resolvedValue{}
	}
	// If this is a *ssa.Return object, i.e. we are analyzing the function
	// and not the call site, then we can just pull the result directly.
	if ret, ok := rv.(*ssa.Return); ok {
		return makeResolvedValue(ret.Results[r.Index], r.FieldList)
	}
	if r.NeedsExtract {
		// Resolve on the extracted field, this is necessary if the
		// type here is not an explicit return. Note that rv must be an
		// ssa.Value, since it is not an *ssa.Return.
		v := rv.(ssa.Value)
		if refs := v.Referrers(); refs != nil {
			for _, inst := range *refs {
				if x, ok := inst.(*ssa.Extract); ok && x.Tuple == v && x.Index == r.Index {
					return makeResolvedValue(x, r.FieldList)
				}
			}
		}
		// Nothing resolved.
		return resolvedValue{}
	}
	if r.Index != 0 {
		// This should not happen, NeedsExtract should always be set.
		panic("NeedsExtract is false, but return value index is non-zero")
	}
	// Resolve on the single return.
	return makeResolvedValue(rv.(ssa.Value), r.FieldList)
}

// resolveStatic implements functionGuardResolver.resolveStatic.
func (r *returnGuard) resolveStatic(_ *passContext, _ *lockState, _ *ssa.Function, rv any) resolvedValue {
	return r.resolveCommon(rv)
}

// resolveCall implements functionGuardResolver.resolveCall.
func (r *returnGuard) resolveCall(_ *passContext, _ *lockState, _ []ssa.Value, rv ssa.Value) resolvedValue {
	return r.resolveCommon(rv)
}

// functionGuardInfo is information about a method guard.
type functionGuardInfo struct {
	// Resolver is the resolver for this guard.
	Resolver functionGuardResolver

	// IsAlias indicates that this guard is an alias.
	IsAlias bool

	// Exclusive indicates an exclusive lock is required.
	Exclusive bool
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
	// HeldOnEntry: {"a.mu" => {Resolver: &parameterGuard{Index: 0}}
	HeldOnEntry map[string]functionGuardInfo

	// HeldOnExit tracks the locks that are expected to be held on exit.
	HeldOnExit map[string]functionGuardInfo

	// Ignore means this function has local analysis ignores.
	//
	// This is not used outside the local package.
	Ignore bool
}

// AFact implements analysis.Fact.AFact.
func (*lockFunctionFacts) AFact() {}

// checkGuard validates the guardName.
func (lff *lockFunctionFacts) checkGuard(pc *passContext, d *ast.FuncDecl, guardName string, exclusive bool, allowReturn bool) (functionGuardInfo, bool) {
	if _, ok := lff.HeldOnEntry[guardName]; ok {
		pc.maybeFail(d.Pos(), "annotation %s specified more than once, already required", guardName)
		return functionGuardInfo{}, false
	}
	if _, ok := lff.HeldOnExit[guardName]; ok {
		pc.maybeFail(d.Pos(), "annotation %s specified more than once, already acquired", guardName)
		return functionGuardInfo{}, false
	}
	fg, ok := pc.findFunctionGuard(d, guardName, exclusive, allowReturn)
	return fg, ok
}

// addGuardedBy adds a field to both HeldOnEntry and HeldOnExit.
func (lff *lockFunctionFacts) addGuardedBy(pc *passContext, d *ast.FuncDecl, guardName string, exclusive bool) {
	if fg, ok := lff.checkGuard(pc, d, guardName, exclusive, false /* allowReturn */); ok {
		if lff.HeldOnEntry == nil {
			lff.HeldOnEntry = make(map[string]functionGuardInfo)
		}
		if lff.HeldOnExit == nil {
			lff.HeldOnExit = make(map[string]functionGuardInfo)
		}
		lff.HeldOnEntry[guardName] = fg
		lff.HeldOnExit[guardName] = fg
	}
}

// addAcquires adds a field to HeldOnExit.
func (lff *lockFunctionFacts) addAcquires(pc *passContext, d *ast.FuncDecl, guardName string, exclusive bool) {
	if fg, ok := lff.checkGuard(pc, d, guardName, exclusive, true /* allowReturn */); ok {
		if lff.HeldOnExit == nil {
			lff.HeldOnExit = make(map[string]functionGuardInfo)
		}
		lff.HeldOnExit[guardName] = fg
	}
}

// addReleases adds a field to HeldOnEntry.
func (lff *lockFunctionFacts) addReleases(pc *passContext, d *ast.FuncDecl, guardName string, exclusive bool) {
	if fg, ok := lff.checkGuard(pc, d, guardName, exclusive, false /* allowReturn */); ok {
		if lff.HeldOnEntry == nil {
			lff.HeldOnEntry = make(map[string]functionGuardInfo)
		}
		lff.HeldOnEntry[guardName] = fg
	}
}

// addAlias adds an alias.
func (lff *lockFunctionFacts) addAlias(pc *passContext, d *ast.FuncDecl, guardName string) {
	// Parse the alias.
	parts := strings.Split(guardName, "=")
	if len(parts) != 2 {
		pc.maybeFail(d.Pos(), "invalid annotation %s for alias", guardName)
		return
	}

	// Parse the actual guard.
	fg, ok := lff.checkGuard(pc, d, parts[0], true /* exclusive */, true /* allowReturn */)
	if !ok {
		return
	}
	fg.IsAlias = true

	// Find the existing specification.
	_, entryOk := lff.HeldOnEntry[parts[1]]
	if entryOk {
		lff.HeldOnEntry[guardName] = fg
	}
	_, exitOk := lff.HeldOnExit[parts[1]]
	if exitOk {
		lff.HeldOnExit[guardName] = fg
	}
	if !entryOk && !exitOk {
		pc.maybeFail(d.Pos(), "alias annotation %s does not refer to an existing guard", guardName)
	}
}

// fieldEntryFor returns the fieldList value for the given object.
func (pc *passContext) fieldEntryFor(fieldObj types.Object, index int) fieldEntry {

	// Return the resolution path.
	if _, ok := fieldObj.Type().Underlying().(*types.Pointer); ok {
		return fieldStructPtr(index)
	}
	if _, ok := fieldObj.Type().Underlying().(*types.Interface); ok {
		return fieldStructPtr(index)
	}
	return fieldStruct(index)
}

// findField resolves a field in a single struct.
func (pc *passContext) findField(structType *types.Struct, fieldName string) (fl fieldList, fieldObj types.Object, ok bool) {
	// Scan to match the next field.
	for i := 0; i < structType.NumFields(); i++ {
		fieldObj := structType.Field(i)
		if fieldObj.Name() != fieldName {
			continue
		}
		fl = append(fl, pc.fieldEntryFor(fieldObj, i))
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
		flEmbed := pc.fieldEntryFor(fieldObj, i)
		flNext, fieldObjNext, ok := pc.findField(structType, fieldName)
		if !ok {
			continue
		}

		// Found an embedded chain.
		fl = append(fl, flEmbed)
		fl = append(fl, flNext...)
		return fl, fieldObjNext, true
	}

	return nil, nil, false
}

var (
	mutexRE   = regexp.MustCompile(".*Mutex")
	rwMutexRE = regexp.MustCompile(".*RWMutex")
	lockerRE  = regexp.MustCompile(".*sync.Locker")
)

// validateMutex validates the mutex type.
//
// This function returns true iff the object is a valid mutex with an error
// reported at the given position if necessary.
func (pc *passContext) validateMutex(pos token.Pos, obj types.Object, exclusive bool) bool {
	// Check that it is indeed a mutex.
	s := obj.Type().String()
	switch {
	case rwMutexRE.MatchString(s):
		// Safe for all cases.
		return true
	case mutexRE.MatchString(s), lockerRE.MatchString(s):
		// Safe for exclusive cases.
		if !exclusive {
			pc.maybeFail(pos, "field %s must be a RWMutex", obj.Name())
			return false
		}
		return true
	default:
		// Not a mutex at all?
		pc.maybeFail(pos, "field %s is not a Mutex or an RWMutex", obj.Name())
		return false
	}
}

// findFieldList resolves a set of fields given a string, such a 'a.b.c'.
//
// Note that parts must be non-zero in length. If it may be zero, then
// maybeFindFieldList should be used instead with an appropriate object.
func (pc *passContext) findFieldList(pos token.Pos, structType *types.Struct, parts []string, exclusive bool) (fl fieldList, ok bool) {
	var obj types.Object

	// This loop requires at least one iteration in order to ensure that
	// obj above is non-nil, and the type can be validated.
	for i, fieldName := range parts {
		flOne, fieldObj, ok := pc.findField(structType, fieldName)
		if !ok {
			return nil, false
		}
		fl = append(fl, flOne...)
		obj = fieldObj
		if i < len(parts)-1 {
			structType, ok = resolveStruct(obj.Type())
			if !ok {
				// N.B. This is associated with the original position.
				pc.maybeFail(pos, "field %s expected to be struct", fieldName)
				return nil, false
			}
		}
	}

	// Validate the final field. This reports the field to the caller
	// anyways, since the error will be reported only once.
	_ = pc.validateMutex(pos, obj, exclusive)
	return fl, true
}

// maybeFindFieldList resolves the given object.
//
// Parts may be the empty list, unlike findFieldList.
func (pc *passContext) maybeFindFieldList(pos token.Pos, obj types.Object, parts []string, exclusive bool) (fl fieldList, ok bool) {
	if len(parts) > 0 {
		structType, ok := resolveStruct(obj.Type())
		if !ok {
			// This does not have any fields; the access is not allowed.
			pc.maybeFail(pos, "attempted field access on non-struct")
			return nil, false
		}
		return pc.findFieldList(pos, structType, parts, exclusive)
	}

	// See above.
	_ = pc.validateMutex(pos, obj, exclusive)
	return nil, true
}

// findFieldGuardResolver finds a symbol resolver.
type findFieldGuardResolver func(pos token.Pos, guardName string) (fieldGuardResolver, bool)

// findFunctionGuardResolver finds a symbol resolver.
type findFunctionGuardResolver func(pos token.Pos, guardName string) (functionGuardResolver, bool)

// fillLockGuardFacts fills the facts with guard information.
func (pc *passContext) fillLockGuardFacts(obj types.Object, cg *ast.CommentGroup, find findFieldGuardResolver, lgf *lockGuardFacts) {
	if cg == nil {
		return
	}
	for _, l := range cg.List {
		pc.extractAnnotations(l.Text, map[string]func(string){
			checkAtomicAnnotation: func(string) {
				switch lgf.AtomicDisposition {
				case atomicRequired:
					pc.maybeFail(obj.Pos(), "annotation is redundant, already atomic required")
				case atomicIgnore:
					pc.maybeFail(obj.Pos(), "annotation is contradictory, already atomic ignored")
				}
				lgf.AtomicDisposition = atomicRequired
			},
			checkLocksIgnore: func(string) {
				switch lgf.AtomicDisposition {
				case atomicIgnore:
					pc.maybeFail(obj.Pos(), "annotation is redundant, already atomic ignored")
				case atomicRequired:
					pc.maybeFail(obj.Pos(), "annotation is contradictory, already atomic required")
				}
				lgf.AtomicDisposition = atomicIgnore
			},
			checkLocksAnnotation: func(guardName string) {
				// Check for a duplicate annotation.
				if _, ok := lgf.GuardedBy[guardName]; ok {
					pc.maybeFail(obj.Pos(), "annotation %s specified more than once", guardName)
					return
				}
				// Add the item.
				if lgf.GuardedBy == nil {
					lgf.GuardedBy = make(map[string]fieldGuardResolver)
				}
				fr, ok := find(obj.Pos(), guardName)
				if !ok {
					pc.maybeFail(obj.Pos(), "annotation %s cannot be resolved", guardName)
					return
				}
				lgf.GuardedBy[guardName] = fr
			},
			// N.B. We support only the vanilla annotation on
			// individual fields. If the field is a read lock, then
			// we will allow read access by default.
			checkLocksAnnotationRead: func(guardName string) {
				pc.maybeFail(obj.Pos(), "annotation %s not legal on fields", guardName)
			},
		})
	}
	// Save only if there is something meaningful.
	if len(lgf.GuardedBy) > 0 || lgf.AtomicDisposition != atomicDisallow {
		pc.pass.ExportObjectFact(obj, lgf)
	}
}

// findGlobalGuard attempts to resolve a name globally.
func (pc *passContext) findGlobalGuard(pos token.Pos, guardName string) (*globalGuard, bool) {
	// Attempt to resolve the object.
	parts := strings.Split(guardName, ".")
	globalObj := pc.pass.Pkg.Scope().Lookup(parts[0])
	if globalObj == nil {
		// No global object.
		return nil, false
	}
	fl, ok := pc.maybeFindFieldList(pos, globalObj, parts[1:], true /* exclusive */)
	if !ok {
		// Invalid fields.
		return nil, false
	}
	return &globalGuard{
		ObjectName:  parts[0],
		PackageName: pc.pass.Pkg.Path(),
		FieldList:   fl,
	}, true
}

// findGlobalFieldGuard is compatible with findFieldGuardResolver.
func (pc *passContext) findGlobalFieldGuard(pos token.Pos, guardName string) (fieldGuardResolver, bool) {
	g, ok := pc.findGlobalGuard(pos, guardName)
	return g, ok
}

// findGlobalFunctionGuard is compatible with findFunctionGuardResolver.
func (pc *passContext) findGlobalFunctionGuard(pos token.Pos, guardName string) (functionGuardResolver, bool) {
	g, ok := pc.findGlobalGuard(pos, guardName)
	return g, ok
}

// structLockGuardFacts finds all relevant guard information for structures.
func (pc *passContext) structLockGuardFacts(structType *types.Struct, ss *ast.StructType) {
	var fieldObj *types.Var
	findLocal := func(pos token.Pos, guardName string) (fieldGuardResolver, bool) {
		// Try to resolve from the local structure first.
		fl, ok := pc.findFieldList(pos, structType, strings.Split(guardName, "."), true /* exclusive */)
		if ok {
			// Found a valid resolution.
			return &fieldGuard{
				FieldList: fl,
			}, true
		}
		// Attempt a global resolution.
		return pc.findGlobalFieldGuard(pos, guardName)
	}
	for i, field := range ss.Fields.List {
		var lgf lockGuardFacts
		fieldObj = structType.Field(i) // N.B. Captured above.
		pc.fillLockGuardFacts(fieldObj, field.Doc, findLocal, &lgf)

		// See above, for anonymous structure fields.
		if ss, ok := field.Type.(*ast.StructType); ok {
			if st, ok := fieldObj.Type().(*types.Struct); ok {
				pc.structLockGuardFacts(st, ss)
			}
		}
	}
}

// globalLockGuardFacts finds all relevant guard information for globals.
//
// Note that the Type is checked in checklocks.go at the top-level.
func (pc *passContext) globalLockGuardFacts(vs *ast.ValueSpec) {
	var lgf lockGuardFacts
	globalObj := pc.pass.TypesInfo.ObjectOf(vs.Names[0])
	pc.fillLockGuardFacts(globalObj, vs.Doc, pc.findGlobalFieldGuard, &lgf)
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
//
// This function may or may not report an error. This is indicated in the
// reported return value. If reported is true, then the specification is
// ambiguous or not valid, and should be propagated.
func (pc *passContext) matchFieldList(pos token.Pos, fields []*ast.Field, guardName string, exclusive bool) (number int, fl fieldList, reported, ok bool) {
	parts := strings.Split(guardName, ".")
	firstName := parts[0]
	index := 0
	for _, field := range fields {
		// See countFields, above.
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, name := range field.Names {
			if name.Name != firstName {
				index++
				continue
			}
			obj := pc.pass.TypesInfo.ObjectOf(name)
			fl, ok := pc.maybeFindFieldList(pos, obj, parts[1:], exclusive)
			if !ok {
				// Some intermediate name does not match. The
				// resolveField function will not report.
				pc.maybeFail(pos, "name %s does not resolve to a field", guardName)
				return 0, nil, true, false
			}
			// Successfully found a field.
			return index, fl, false, true
		}
	}

	// Nothing matching.
	return 0, nil, false, false
}

// findFunctionGuard identifies the parameter number and field number for a
// particular string of the 'a.b'.
//
// This function will report any errors directly.
func (pc *passContext) findFunctionGuard(d *ast.FuncDecl, guardName string, exclusive bool, allowReturn bool) (functionGuardInfo, bool) {
	// Match against receiver & parameters.
	var parameterList []*ast.Field
	if d.Recv != nil {
		parameterList = append(parameterList, d.Recv.List...)
	}
	if d.Type.Params != nil {
		parameterList = append(parameterList, d.Type.Params.List...)
	}
	if index, fl, reported, ok := pc.matchFieldList(d.Pos(), parameterList, guardName, exclusive); reported || ok {
		if !ok {
			return functionGuardInfo{}, false
		}
		return functionGuardInfo{
			Resolver: &parameterGuard{
				Index:     index,
				FieldList: fl,
			},
			Exclusive: exclusive,
		}, true
	}

	// Match against return values, if allowed.
	if allowReturn {
		var returnList []*ast.Field
		if d.Type.Results != nil {
			returnList = append(returnList, d.Type.Results.List...)
		}
		if index, fl, reported, ok := pc.matchFieldList(d.Pos(), returnList, guardName, exclusive); reported || ok {
			if !ok {
				return functionGuardInfo{}, false
			}
			return functionGuardInfo{
				Resolver: &returnGuard{
					Index:        index,
					FieldList:    fl,
					NeedsExtract: countFields(returnList) > 1,
				},
				Exclusive: exclusive,
			}, true
		}
	}

	// Match against globals.
	if g, ok := pc.findGlobalFunctionGuard(d.Pos(), guardName); ok {
		return functionGuardInfo{
			Resolver:  g,
			Exclusive: exclusive,
		}, true
	}

	// No match found.
	pc.maybeFail(d.Pos(), "annotation %s does not have a match any parameter, return value or global", guardName)
	return functionGuardInfo{}, false
}

// functionFacts exports relevant function findings.
func (pc *passContext) functionFacts(d *ast.FuncDecl) {
	// Extract guard information.
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
			checkLocksAnnotation:     func(guardName string) { lff.addGuardedBy(pc, d, guardName, true /* exclusive */) },
			checkLocksAnnotationRead: func(guardName string) { lff.addGuardedBy(pc, d, guardName, false /* exclusive */) },
			checkLocksAcquires:       func(guardName string) { lff.addAcquires(pc, d, guardName, true /* exclusive */) },
			checkLocksAcquiresRead:   func(guardName string) { lff.addAcquires(pc, d, guardName, false /* exclusive */) },
			checkLocksReleases:       func(guardName string) { lff.addReleases(pc, d, guardName, true /* exclusive */) },
			checkLocksReleasesRead:   func(guardName string) { lff.addReleases(pc, d, guardName, false /* exclusive */) },
			checkLocksAlias:          func(guardName string) { lff.addAlias(pc, d, guardName) },
		})
	}

	// Export the function facts if there is anything to save.
	if lff.Ignore || len(lff.HeldOnEntry) > 0 || len(lff.HeldOnExit) > 0 {
		funcObj := pc.pass.TypesInfo.Defs[d.Name].(*types.Func)
		pc.pass.ExportObjectFact(funcObj, &lff)
	}
}

func init() {
	gob.Register((*returnGuard)(nil))
	gob.Register((*globalGuard)(nil))
	gob.Register((*parameterGuard)(nil))
	gob.Register((*fieldGuard)(nil))
	gob.Register((*fieldStructPtr)(nil))
	gob.Register((*fieldStruct)(nil))
}
