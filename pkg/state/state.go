// Copyright 2018 Google Inc.
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

// Package state provides functionality related to saving and loading object
// graphs.  For most types, it provides a set of default saving / loading logic
// that will be invoked automatically if custom logic is not defined.
//
//     Kind             Support
//     ----             -------
//     Bool             default
//     Int              default
//     Int8             default
//     Int16            default
//     Int32            default
//     Int64            default
//     Uint             default
//     Uint8            default
//     Uint16           default
//     Uint32           default
//     Uint64           default
//     Float32          default
//     Float64          default
//     Complex64        custom
//     Complex128       custom
//     Array            default
//     Chan             custom
//     Func             custom
//     Interface        custom
//     Map              default (*)
//     Ptr              default
//     Slice            default
//     String           default
//     Struct           custom
//     UnsafePointer    custom
//
// (*) Maps are treated as value types by this package, even if they are
// pointers internally. If you want to save two independent references
// to the same map value, you must explicitly use a pointer to a map.
package state

import (
	"fmt"
	"io"
	"reflect"
	"runtime"

	pb "gvisor.googlesource.com/gvisor/pkg/state/object_go_proto"
)

// ErrState is returned when an error is encountered during encode/decode.
type ErrState struct {
	// Err is the underlying error.
	Err error

	// path is the visit path from root to the current object.
	path string

	// trace is the stack trace.
	trace string
}

// Error returns a sensible description of the state error.
func (e *ErrState) Error() string {
	return fmt.Sprintf("%v:\nstate path: %s\n%s", e.Err, e.path, e.trace)
}

// Save saves the given object state.
func Save(w io.Writer, rootPtr interface{}, stats *Stats) error {
	// Create the encoding state.
	es := &encodeState{
		idsByObject: make(map[uintptr]uint64),
		w:           w,
		stats:       stats,
	}

	// Perform the encoding.
	return es.safely(func() {
		es.Serialize(reflect.ValueOf(rootPtr).Elem())
	})
}

// Load loads a checkpoint.
func Load(r io.Reader, rootPtr interface{}, stats *Stats) error {
	// Create the decoding state.
	ds := &decodeState{
		objectsByID: make(map[uint64]*objectState),
		deferred:    make(map[uint64]*pb.Object),
		r:           r,
		stats:       stats,
	}

	// Attempt our decode.
	return ds.safely(func() {
		ds.Deserialize(reflect.ValueOf(rootPtr).Elem())
	})
}

// Fns are the state dispatch functions.
type Fns struct {
	// Save is a function like Save(concreteType, Map).
	Save interface{}

	// Load is a function like Load(concreteType, Map).
	Load interface{}
}

// Save executes the save function.
func (fns *Fns) invokeSave(obj reflect.Value, m Map) {
	reflect.ValueOf(fns.Save).Call([]reflect.Value{obj, reflect.ValueOf(m)})
}

// Load executes the load function.
func (fns *Fns) invokeLoad(obj reflect.Value, m Map) {
	reflect.ValueOf(fns.Load).Call([]reflect.Value{obj, reflect.ValueOf(m)})
}

// validateStateFn ensures types are correct.
func validateStateFn(fn interface{}, typ reflect.Type) bool {
	fnTyp := reflect.TypeOf(fn)
	if fnTyp.Kind() != reflect.Func {
		return false
	}
	if fnTyp.NumIn() != 2 {
		return false
	}
	if fnTyp.NumOut() != 0 {
		return false
	}
	if fnTyp.In(0) != typ {
		return false
	}
	if fnTyp.In(1) != reflect.TypeOf(Map{}) {
		return false
	}
	return true
}

// Validate validates all state functions.
func (fns *Fns) Validate(typ reflect.Type) bool {
	return validateStateFn(fns.Save, typ) && validateStateFn(fns.Load, typ)
}

type typeDatabase struct {
	// nameToType is a forward lookup table.
	nameToType map[string]reflect.Type

	// typeToName is the reverse lookup table.
	typeToName map[reflect.Type]string

	// typeToFns is the function lookup table.
	typeToFns map[reflect.Type]Fns
}

// registeredTypes is a database used for SaveInterface and LoadInterface.
var registeredTypes = typeDatabase{
	nameToType: make(map[string]reflect.Type),
	typeToName: make(map[reflect.Type]string),
	typeToFns:  make(map[reflect.Type]Fns),
}

// register registers a type under the given name. This will generally be
// called via init() methods, and therefore uses panic to propagate errors.
func (t *typeDatabase) register(name string, typ reflect.Type, fns Fns) {
	// We can't allow name collisions.
	if ot, ok := t.nameToType[name]; ok {
		panic(fmt.Sprintf("type %q can't use name %q, already in use by type %q", typ.Name(), name, ot.Name()))
	}

	// Or multiple registrations.
	if on, ok := t.typeToName[typ]; ok {
		panic(fmt.Sprintf("type %q can't be registered as %q, already registered as %q", typ.Name(), name, on))
	}

	t.nameToType[name] = typ
	t.typeToName[typ] = name
	t.typeToFns[typ] = fns
}

// lookupType finds a type given a name.
func (t *typeDatabase) lookupType(name string) (reflect.Type, bool) {
	typ, ok := t.nameToType[name]
	return typ, ok
}

// lookupName finds a name given a type.
func (t *typeDatabase) lookupName(typ reflect.Type) (string, bool) {
	name, ok := t.typeToName[typ]
	return name, ok
}

// lookupFns finds functions given a type.
func (t *typeDatabase) lookupFns(typ reflect.Type) (Fns, bool) {
	fns, ok := t.typeToFns[typ]
	return fns, ok
}

// Register must be called for any interface implementation types that
// implements Loader.
//
// Register should be called either immediately after startup or via init()
// methods. Double registration of either names or types will result in a panic.
//
// No synchronization is provided; this should only be called in init.
//
// Example usage:
//
// 	state.Register("Foo", (*Foo)(nil), state.Fns{
//		Save: (*Foo).Save,
//		Load: (*Foo).Load,
//	})
//
func Register(name string, instance interface{}, fns Fns) {
	registeredTypes.register(name, reflect.TypeOf(instance), fns)
}

// IsZeroValue checks if the given value is the zero value.
//
// This function is used by the stateify tool.
func IsZeroValue(val interface{}) bool {
	if val == nil {
		return true
	}
	return reflect.DeepEqual(val, reflect.Zero(reflect.TypeOf(val)).Interface())
}

// step captures one encoding / decoding step. On each step, there is up to one
// choice made, which is captured by non-nil param. We intentionally do not
// eagerly create the final path string, as that will only be needed upon panic.
type step struct {
	// dereference indicate if the current object is obtained by
	// dereferencing a pointer.
	dereference bool

	// format is the formatting string that takes param below, if
	// non-nil. For example, in array indexing case, we have "[%d]".
	format string

	// param stores the choice made at the current encoding / decoding step.
	// For eaxmple, in array indexing case, param stores the index. When no
	// choice is made, e.g. dereference, param should be nil.
	param interface{}
}

// recoverable is the state encoding / decoding panic recovery facility. It is
// also used to store encoding / decoding steps as well as the reference to the
// original queued object from which the current object is dispatched. The
// complete encoding / decoding path is synthesised from the steps in all queued
// objects leading to the current object.
type recoverable struct {
	from  *recoverable
	steps []step
}

// push enters a new context level.
func (sr *recoverable) push(dereference bool, format string, param interface{}) {
	sr.steps = append(sr.steps, step{dereference, format, param})
}

// pop exits the current context level.
func (sr *recoverable) pop() {
	if len(sr.steps) <= 1 {
		return
	}
	sr.steps = sr.steps[:len(sr.steps)-1]
}

// path returns the complete encoding / decoding path from root. This is only
// called upon panic.
func (sr *recoverable) path() string {
	if sr.from == nil {
		return "root"
	}
	p := sr.from.path()
	for _, s := range sr.steps {
		if s.dereference {
			p = fmt.Sprintf("*(%s)", p)
		}
		if s.param == nil {
			p += s.format
		} else {
			p += fmt.Sprintf(s.format, s.param)
		}
	}
	return p
}

func (sr *recoverable) copy() recoverable {
	return recoverable{from: sr.from, steps: append([]step(nil), sr.steps...)}
}

// safely executes the given function, catching a panic and unpacking as an error.
//
// The error flow through the state package uses panic and recover. There are
// two important reasons for this:
//
// 1) Many of the reflection methods will already panic with invalid data or
// violated assumptions. We would want to recover anyways here.
//
// 2) It allows us to eliminate boilerplate within Save() and Load() functions.
// In nearly all cases, when the low-level serialization functions fail, you
// will want the checkpoint to fail anyways. Plumbing errors through every
// method doesn't add a lot of value. If there are specific error conditions
// that you'd like to handle, you should add appropriate functionality to
// objects themselves prior to calling Save() and Load().
func (sr *recoverable) safely(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			es := new(ErrState)
			if e, ok := r.(error); ok {
				es.Err = e
			} else {
				es.Err = fmt.Errorf("%v", r)
			}

			es.path = sr.path()

			// Make a stack. We don't know how big it will be ahead
			// of time, but want to make sure we get the whole
			// thing. So we just do a stupid brute force approach.
			var stack []byte
			for sz := 1024; ; sz *= 2 {
				stack = make([]byte, sz)
				n := runtime.Stack(stack, false)
				if n < sz {
					es.trace = string(stack[:n])
					break
				}
			}

			// Set the error.
			err = es
		}
	}()

	// Execute the function.
	fn()
	return nil
}
