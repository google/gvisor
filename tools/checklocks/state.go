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
	"go/token"
	"go/types"
	"strings"
	"sync/atomic"

	"golang.org/x/tools/go/ssa"
)

// lockInfo describes a held lock.
type lockInfo struct {
	exclusive bool
	object    types.Object
}

// lockState tracks the locking state and aliases.
type lockState struct {
	// lockedMutexes is used to track which mutexes in a given struct are
	// currently locked. Note that most of the heavy lifting is done by
	// valueAndObject below, which maps to specific structure fields, etc.
	//
	// The value indicates whether this is an exclusive lock.
	lockedMutexes map[string]lockInfo

	// stored stores values that have been stored in memory, bound to
	// FreeVars or passed as Parameterse.
	stored map[ssa.Value]ssa.Value

	// used is a temporary map, used only for valueAndObject. It prevents
	// multiple use of the same memory location.
	used map[ssa.Value]struct{}

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
		used:          make(map[ssa.Value]struct{}),
		stored:        make(map[ssa.Value]ssa.Value),
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
		used:          make(map[ssa.Value]struct{}),
		stored:        l.stored,
		defers:        l.defers,
		refs:          l.refs,
	}
}

// modify indicates that this state will be modified.
func (l *lockState) modify() {
	if atomic.LoadInt32(l.refs) > 1 {
		// Copy the lockedMutexes.
		lm := make(map[string]lockInfo)
		for k, v := range l.lockedMutexes {
			lm[k] = v
		}
		l.lockedMutexes = lm

		// Copy the stored values.
		s := make(map[ssa.Value]ssa.Value)
		for k, v := range l.stored {
			s[k] = v
		}
		l.stored = s

		// Reset the used values.
		l.used = make(map[ssa.Value]struct{})

		// Copy the defers.
		ds := make([]*ssa.Defer, len(l.defers))
		copy(ds, l.defers)
		l.defers = ds

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

// store records an alias.
func (l *lockState) store(addr ssa.Value, v ssa.Value) {
	l.modify()
	l.stored[addr] = v
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
	switch x := v.(type) {
	case *ssa.Parameter:
		// Was this provided as a paramter for a local anonymous
		// function invocation?
		v, ok := l.stored[x]
		if ok {
			return l.valueAndObject(v)
		}
		return fmt.Sprintf("{param:%s}", x.Name()), x.Object()
	case *ssa.Global:
		return fmt.Sprintf("{global:%s}", x.Name()), x.Object()
	case *ssa.FreeVar:
		// Attempt to resolve this, in case we are being invoked in a
		// scope where all the variables are bound.
		v, ok := l.stored[x]
		if ok {
			// The FreeVar is typically bound to a location, so we
			// check what's been stored there. Note that the second
			// may map to the same FreeVar, which we can check.
			stored, ok := l.stored[v]
			if ok {
				return l.valueAndObject(stored)
			}
		}
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
		if x.Op != token.MUL {
			break
		}
		// Is this loading a free variable? If yes, then this can be
		// resolved in the original isAlias function.
		if fv, ok := x.X.(*ssa.FreeVar); ok {
			return l.valueAndObject(fv)
		}
		// Should be try to resolve via a memory address? This needs to
		// be done since a memory location can hold its own value.
		if _, ok := l.used[x.X]; !ok {
			// Check if we know what the accessed location holds.
			// This is used to disambiguate memory locations.
			v, ok := l.stored[x.X]
			if ok {
				l.used[x.X] = struct{}{}
				defer func() { delete(l.used, x.X) }()
				return l.valueAndObject(v)
			}
		}
		// x.X.Type is pointer. We must construct this type
		// dynamically, since the ssa.Value could be synthetic.
		s, obj := l.valueAndObject(x.X)
		return fmt.Sprintf("*(%s)", s), obj
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
