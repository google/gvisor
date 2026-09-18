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
	"go/types"
	"maps"
	"slices"
	"strings"
	"sync/atomic"

	"golang.org/x/tools/go/ssa"
)

// lockInfo describes a held lock.
type lockInfo struct {
	exclusive bool
	object    types.Object
}

// valueIdentity preserves the identity resolved when a value was evaluated.
type valueIdentity struct {
	key    string
	object types.Object
}

// lockState tracks the locking state and aliases.
type lockState struct {
	// lockedMutexes is used to track which mutexes in a given struct are
	// currently locked. Note that most of the heavy lifting is done by
	// valueAndObject below, which maps to specific structure fields, etc.
	//
	// The value indicates whether this is an exclusive lock.
	lockedMutexes map[string]lockInfo

	aliases map[string]string

	// bindings substitutes parameters and captured addresses at inline calls.
	bindings map[ssa.Value]ssa.Value

	// stored maps resolved memory addresses to their known contents. Reads
	// cache the initial contents, so a join can distinguish unchanged memory
	// from a value that is no longer known.
	stored map[string]valueIdentity

	// unknownMemory means that an absent stored entry no longer identifies
	// untouched initial memory. Reads instead assign a fresh identity and
	// cache it until the contents change or a join loses that fact.
	unknownMemory bool

	// memoryIDs allocates identities shared across forks and inline calls.
	// Its progress is not part of the facts compared at control-flow joins.
	memoryIDs *atomic.Uint64

	// loaded records evaluated values independently of subsequent stores.
	loaded map[*ssa.UnOp]valueIdentity

	// defers are the stack of defers that have been pushed.
	defers []*ssa.Defer

	// refs indicates the number of references on this structure. If it's
	// greater than one, we will do copy-on-write.
	refs *int32
}

// newLockState makes a new lockState.
func newLockState() *lockState {
	refs := int32(1) // Not shared.
	return &lockState{
		lockedMutexes: make(map[string]lockInfo),
		aliases:       make(map[string]string),
		bindings:      make(map[ssa.Value]ssa.Value),
		stored:        make(map[string]valueIdentity),
		memoryIDs:     new(atomic.Uint64),
		loaded:        make(map[*ssa.UnOp]valueIdentity),
		defers:        make([]*ssa.Defer, 0),
		refs:          &refs,
	}
}

// fork forks the locking state. When a lockState is forked, any modifications
// will cause maps to be copied.
func (l *lockState) fork() *lockState {
	if l == nil {
		return newLockState()
	}
	atomic.AddInt32(l.refs, 1)
	return &lockState{
		lockedMutexes: l.lockedMutexes,
		aliases:       l.aliases,
		bindings:      l.bindings,
		stored:        l.stored,
		unknownMemory: l.unknownMemory,
		memoryIDs:     l.memoryIDs,
		loaded:        l.loaded,
		defers:        l.defers,
		refs:          l.refs,
	}
}

// modify indicates that this state will be modified.
func (l *lockState) modify() {
	if atomic.LoadInt32(l.refs) > 1 {
		// Copy the lockedMutexes.
		l.lockedMutexes = maps.Clone(l.lockedMutexes)

		// Copy the aliases.
		l.aliases = maps.Clone(l.aliases)

		// Copy the stored values.
		l.bindings = maps.Clone(l.bindings)
		l.stored = maps.Clone(l.stored)
		l.loaded = maps.Clone(l.loaded)

		// Copy the defers.
		l.defers = slices.Clone(l.defers)

		// Drop our reference.
		atomic.AddInt32(l.refs, -1)
		newRefs := int32(1) // Not shared.
		l.refs = &newRefs
	}
}

// isHeld indicates whether the field is held is not.
//
// Precondition: rv must be valid.
func (l *lockState) isHeld(rv resolvedValue, exclusiveRequired bool) (string, bool) {
	if !rv.valid() {
		panic("invalid resolvedValue passed to isHeld")
	}
	s, _ := rv.valueAndObject(l)
	s = l.aliasKey(s)
	info, ok := l.lockedMutexes[s]
	if !ok {
		return s, false
	}
	// Accept a weaker lock if exclusiveRequired is false.
	if exclusiveRequired && !info.exclusive {
		return s, false
	}
	return s, true
}

// lockField locks the given field.
//
// If false is returned, the field was already locked.
//
// Precondition: rv must be valid.
func (l *lockState) lockField(rv resolvedValue, exclusive bool) (string, bool) {
	if !rv.valid() {
		panic("invalid resolvedValue passed to isHeld")
	}
	s, obj := rv.valueAndObject(l)
	s = l.aliasKey(s)
	if _, ok := l.lockedMutexes[s]; ok {
		return s, false
	}
	l.modify()
	l.lockedMutexes[s] = lockInfo{
		exclusive: exclusive,
		object:    obj,
	}
	return s, true
}

// unlockField unlocks the given field.
//
// If false is returned, the field was not locked.
//
// Precondition: rv must be valid.
func (l *lockState) unlockField(rv resolvedValue, exclusive bool) (string, bool) {
	if !rv.valid() {
		panic("invalid resolvedValue passed to isHeld")
	}
	s, _ := rv.valueAndObject(l)
	s = l.aliasKey(s)
	info, ok := l.lockedMutexes[s]
	if !ok {
		return s, false
	}
	if info.exclusive != exclusive {
		return s, false
	}
	l.modify()
	delete(l.lockedMutexes, s)
	return s, true
}

// downgradeField downgrades the given field.
//
// If false was returned, the field was not downgraded.
//
// Precondition: rv must be valid.
func (l *lockState) downgradeField(rv resolvedValue) (string, bool) {
	if !rv.valid() {
		panic("invalid resolvedValue passed to isHeld")
	}
	s, _ := rv.valueAndObject(l)
	s = l.aliasKey(s)
	info, ok := l.lockedMutexes[s]
	if !ok {
		return s, false
	}
	if !info.exclusive {
		return s, false
	}
	l.modify()
	info.exclusive = false
	l.lockedMutexes[s] = info // Downgraded.
	return s, true
}

// bound follows bindings from an inline function to its caller.
func (l *lockState) bound(v ssa.Value) ssa.Value {
	for {
		other, ok := l.bindings[v]
		if !ok {
			return v
		}
		v = other
	}
}

func (l *lockState) bind(v, other ssa.Value) {
	l.modify()
	if v == other {
		delete(l.bindings, v)
		return
	}
	other = l.bound(other)
	if v != other {
		l.bindings[v] = other
	}
}

// store records a write, including writes through captured caller variables.
func (l *lockState) store(addr ssa.Value, v ssa.Value) {
	addrKey, _ := l.valueAndObject(addr)
	key, obj := l.valueAndObject(v)
	l.modify()
	l.stored[addrKey] = valueIdentity{key: key, object: obj}
}

// loadValueAndObject resolves the current contents of a memory location.
func (l *lockState) loadValueAndObject(addr ssa.Value) (string, types.Object) {
	key, obj := l.valueAndObject(addr)
	return l.loadKeyAndObject(key, obj)
}

// loadKeyAndObject resolves loads from both SSA addresses and guard paths.
func (l *lockState) loadKeyAndObject(key string, obj types.Object) (string, types.Object) {
	if value, ok := l.stored[key]; ok {
		return value.key, value.object
	}
	value := valueIdentity{key: fmt.Sprintf("*(%s)", key), object: obj}
	if l.unknownMemory {
		value.key = fmt.Sprintf("{memory:%d}", l.memoryIDs.Add(1))
	}
	l.modify()
	l.stored[key] = value
	return value.key, value.object
}

// load snapshots the value when the instruction executes. A deferred argument
// must not be reloaded from its original address when the defer later runs.
func (l *lockState) load(inst *ssa.UnOp) {
	key, obj := l.loadValueAndObject(inst.X)
	l.modify()
	l.loaded[inst] = valueIdentity{key: key, object: obj}
}

// returnFrom imports a synchronous callee's effects while preserving the
// caller's evaluated values, bindings and pending defers.
func (l *lockState) returnFrom(other *lockState) {
	if other == nil {
		return
	}
	bindings, loaded, defers := l.bindings, l.loaded, l.defers
	*l = *other.fork()
	l.bindings, l.loaded, l.defers = bindings, loaded, defers
}

// intersect retains only facts established on both normal return paths.
func (l *lockState) intersect(other *lockState) {
	l.modify()
	maps.DeleteFunc(l.lockedMutexes, func(key string, info lockInfo) bool {
		otherInfo, ok := other.lockedMutexes[key]
		return !ok || info.exclusive != otherInfo.exclusive
	})
	maps.DeleteFunc(l.aliases, func(key, value string) bool { return other.aliases[key] != value })
	maps.DeleteFunc(l.bindings, func(key, value ssa.Value) bool { return other.bindings[key] != value })
	// Once any memory facts disagree, missing entries cannot mean untouched
	// initial contents. Cached reads that agree remain valid across the join.
	l.unknownMemory = l.unknownMemory || other.unknownMemory || !maps.Equal(l.stored, other.stored)
	maps.DeleteFunc(l.stored, func(key string, value valueIdentity) bool { return other.stored[key] != value })
	maps.DeleteFunc(l.loaded, func(key *ssa.UnOp, value valueIdentity) bool { return other.loaded[key] != value })
}

// equivalent includes the facts and pending work that can affect analysis of
// subsequent instructions, not just the locks currently held.
func (l *lockState) equivalent(other *lockState) bool {
	return l.isCompatible(other) && maps.Equal(l.aliases, other.aliases) &&
		maps.Equal(l.bindings, other.bindings) && maps.Equal(l.stored, other.stored) &&
		l.unknownMemory == other.unknownMemory && maps.Equal(l.loaded, other.loaded) &&
		slices.Equal(l.defers, other.defers)
}

func (l *lockState) addAlias(left, right resolvedValue) {
	leftKey, _ := left.valueAndObject(l)
	rightKey, _ := right.valueAndObject(l)
	leftRoot := l.aliasKey(leftKey)
	rightRoot := l.aliasKey(rightKey)
	if leftRoot == rightRoot {
		return
	}
	l.modify()
	l.aliases[leftRoot] = rightRoot
	if leftInfo, ok := l.lockedMutexes[leftRoot]; ok {
		if rightInfo, ok := l.lockedMutexes[rightRoot]; ok {
			leftInfo.exclusive = leftInfo.exclusive || rightInfo.exclusive
		}
		l.lockedMutexes[rightRoot] = leftInfo
		delete(l.lockedMutexes, leftRoot)
	}
}

func (l *lockState) aliasKey(key string) string {
	for {
		parent, ok := l.aliases[key]
		if !ok {
			return key
		}
		key = parent
	}
}

// isSubset indicates other holds all the locks held by l.
func (l *lockState) isSubset(other *lockState) bool {
	for k, info := range l.lockedMutexes {
		otherInfo, otherOk := other.lockedMutexes[k]
		if !otherOk {
			return false
		}
		// Accept weaker locks as a subset.
		if info.exclusive && !otherInfo.exclusive {
			return false
		}
	}
	return true
}

// count indicates the number of locks held.
func (l *lockState) count() int {
	return len(l.lockedMutexes)
}

// isCompatible returns true if the states are compatible.
func (l *lockState) isCompatible(other *lockState) bool {
	return l.isSubset(other) && other.isSubset(l)
}

// elemType is a type that implements the Elem function.
type elemType interface {
	Elem() types.Type
}

// valueAndObject returns a string for a given value, along with a source level
// object (if available and relevant).
//
// This decomposes the value into the simplest possible representation in terms
// of parameters, free variables and globals. During resolution, stored values
// may be transferred, as well as bound free variables.
//
// Nil may not be passed here.
func (l *lockState) valueAndObject(v ssa.Value) (string, types.Object) {
	v = l.bound(v)
	switch x := v.(type) {
	case *ssa.Parameter:
		return fmt.Sprintf("{param:%s}", x.Name()), x.Object()
	case *ssa.Global:
		return fmt.Sprintf("{global:%s}", x.Name()), x.Object()
	case *ssa.FreeVar:
		// FreeVar does not have a corresponding source-level object
		// that we can return here.
		return fmt.Sprintf("{freevar:%s}", x.Name()), nil
	case *ssa.Convert:
		// Just disregard conversion.
		return l.valueAndObject(x.X)
	case *ssa.ChangeType:
		// Ditto, disregard.
		return l.valueAndObject(x.X)
	case *ssa.UnOp:
		if value, ok := l.loaded[x]; ok {
			return value.key, value.object
		}
	case *ssa.Field:
		structType, ok := resolveStruct(x.X.Type())
		if !ok {
			// This should not happen.
			panic(fmt.Sprintf("structType not available for struct: %#v", x.X))
		}
		fieldObj := structType.Field(x.Field)
		s, _ := l.valueAndObject(x.X)
		return fmt.Sprintf("%s.%s", s, fieldObj.Name()), fieldObj
	case *ssa.FieldAddr:
		structType, ok := resolveStruct(x.X.Type())
		if !ok {
			// This should not happen.
			panic(fmt.Sprintf("structType not available for struct: %#v", x.X))
		}
		fieldObj := structType.Field(x.Field)
		s, _ := l.valueAndObject(x.X)
		return fmt.Sprintf("&(%s.%s)", s, fieldObj.Name()), fieldObj
	case *ssa.Index:
		s, _ := l.valueAndObject(x.X)
		i, _ := l.valueAndObject(x.Index)
		return fmt.Sprintf("%s[%s]", s, i), nil
	case *ssa.IndexAddr:
		s, _ := l.valueAndObject(x.X)
		i, _ := l.valueAndObject(x.Index)
		return fmt.Sprintf("&(%s[%s])", s, i), nil
	case *ssa.Lookup:
		s, _ := l.valueAndObject(x.X)
		i, _ := l.valueAndObject(x.Index)
		return fmt.Sprintf("%s[%s]", s, i), nil
	case *ssa.Extract:
		s, _ := l.valueAndObject(x.Tuple)
		return fmt.Sprintf("%s[%d]", s, x.Index), nil
	}

	// In the case of any other type (e.g. this may be an alloc, a return
	// value, etc.), just return the literal pointer value to the Value.
	// This will be unique within the ssa graph, and so if two values are
	// equal, they are from the same type.
	return fmt.Sprintf("{%T:%p}", v, v), nil
}

// String returns the full lock state.
func (l *lockState) String() string {
	if l.count() == 0 {
		return "no locks held"
	}
	keys := make([]string, 0, len(l.lockedMutexes))
	for k, info := range l.lockedMutexes {
		// Include the exclusive status of each lock.
		keys = append(keys, fmt.Sprintf("%s %s", k, exclusiveStr(info.exclusive)))
	}
	return strings.Join(keys, ",")
}

// pushDefer pushes a defer onto the stack.
func (l *lockState) pushDefer(d *ssa.Defer) {
	l.modify()
	l.defers = append(l.defers, d)
}

// popDefer pops a defer from the stack.
func (l *lockState) popDefer() *ssa.Defer {
	// Does not technically modify the underlying slice.
	count := len(l.defers)
	if count == 0 {
		return nil
	}
	d := l.defers[count-1]
	l.defers = l.defers[:count-1]
	return d
}
