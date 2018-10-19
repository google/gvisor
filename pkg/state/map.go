// Copyright 2018 Google LLC
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

package state

import (
	"fmt"
	"reflect"
	"sort"
	"sync"

	pb "gvisor.googlesource.com/gvisor/pkg/state/object_go_proto"
)

// entry is a single map entry.
type entry struct {
	name   string
	object *pb.Object
}

// internalMap is the internal Map state.
//
// These are recycled via a pool to avoid churn.
type internalMap struct {
	// es is encodeState.
	es *encodeState

	// ds is decodeState.
	ds *decodeState

	// os is current object being decoded.
	//
	// This will always be nil during encode.
	os *objectState

	// data stores the encoded values.
	data []entry
}

var internalMapPool = sync.Pool{
	New: func() interface{} {
		return new(internalMap)
	},
}

// newInternalMap returns a cached map.
func newInternalMap(es *encodeState, ds *decodeState, os *objectState) *internalMap {
	m := internalMapPool.Get().(*internalMap)
	m.es = es
	m.ds = ds
	m.os = os
	if m.data != nil {
		m.data = m.data[:0]
	}
	return m
}

// Map is a generic state container.
//
// This is the object passed to Save and Load in order to store their state.
//
// Detailed documentation is available in individual methods.
type Map struct {
	*internalMap
}

// Save adds the given object to the map.
//
// You should pass always pointers to the object you are saving. For example:
//
// type X struct {
// 	A int
// 	B *int
// }
//
// func (x *X) Save(m Map) {
// 	m.Save("A", &x.A)
// 	m.Save("B", &x.B)
// }
//
// func (x *X) Load(m Map) {
// 	m.Load("A", &x.A)
// 	m.Load("B", &x.B)
// }
func (m Map) Save(name string, objPtr interface{}) {
	m.save(name, reflect.ValueOf(objPtr).Elem(), ".%s")
}

// SaveValue adds the given object value to the map.
//
// This should be used for values where pointers are not available, or casts
// are required during Save/Load.
//
// For example, if we want to cast external package type P.Foo to int64:
//
// type X struct {
//	A P.Foo
// }
//
// func (x *X) Save(m Map) {
//	m.SaveValue("A", int64(x.A))
// }
//
// func (x *X) Load(m Map) {
//	m.LoadValue("A", new(int64), func(x interface{}) {
//		x.A = P.Foo(x.(int64))
//	})
// }
func (m Map) SaveValue(name string, obj interface{}) {
	m.save(name, reflect.ValueOf(obj), ".(value %s)")
}

// save is helper for the above. It takes the name of value to save the field
// to, the field object (obj), and a format string that specifies how the
// field's saving logic is dispatched from the struct (normal, value, etc.). The
// format string should expect one string parameter, which is the name of the
// field.
func (m Map) save(name string, obj reflect.Value, format string) {
	if m.es == nil {
		// Not currently encoding.
		m.Failf("no encode state for %q", name)
	}

	// Attempt the encode.
	//
	// These are sorted at the end, after all objects are added and will be
	// sorted and checked for duplicates (see encodeStruct).
	m.data = append(m.data, entry{
		name:   name,
		object: m.es.encodeObject(obj, false, format, name),
	})
}

// Load loads the given object from the map.
//
// See Save for an example.
func (m Map) Load(name string, objPtr interface{}) {
	m.load(name, reflect.ValueOf(objPtr), false, nil, ".%s")
}

// LoadWait loads the given objects from the map, and marks it as requiring all
// AfterLoad executions to complete prior to running this object's AfterLoad.
//
// See Save for an example.
func (m Map) LoadWait(name string, objPtr interface{}) {
	m.load(name, reflect.ValueOf(objPtr), true, nil, ".(wait %s)")
}

// LoadValue loads the given object value from the map.
//
// See SaveValue for an example.
func (m Map) LoadValue(name string, objPtr interface{}, fn func(interface{})) {
	o := reflect.ValueOf(objPtr)
	m.load(name, o, true, func() { fn(o.Elem().Interface()) }, ".(value %s)")
}

// load is helper for the above. It takes the name of value to load the field
// from, the target field pointer (objPtr), whether load completion of the
// struct depends on the field's load completion (wait), the load completion
// logic (fn), and a format string that specifies how the field's loading logic
// is dispatched from the struct (normal, wait, value, etc.). The format string
// should expect one string parameter, which is the name of the field.
func (m Map) load(name string, objPtr reflect.Value, wait bool, fn func(), format string) {
	if m.ds == nil {
		// Not currently decoding.
		m.Failf("no decode state for %q", name)
	}

	// Find the object.
	//
	// These are sorted up front (and should appear in the state file
	// sorted as well), so we can do a binary search here to ensure that
	// large structs don't behave badly.
	i := sort.Search(len(m.data), func(i int) bool {
		return m.data[i].name >= name
	})
	if i >= len(m.data) || m.data[i].name != name {
		// There is no data for this name?
		m.Failf("no data found for %q", name)
	}

	// Perform the decode.
	m.ds.decodeObject(m.os, objPtr.Elem(), m.data[i].object, format, name)
	if wait {
		// Mark this individual object a blocker.
		m.ds.waitObject(m.os, m.data[i].object, fn)
	}
}

// Failf fails the save or restore with the provided message. Processing will
// stop after calling Failf, as the state package uses a panic & recover
// mechanism for state errors. You should defer any cleanup required.
func (m Map) Failf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args...))
}

// AfterLoad schedules a function execution when all objects have been allocated
// and their automated loading and customized load logic have been executed. fn
// will not be executed until all of current object's dependencies' AfterLoad()
// logic, if exist, have been executed.
func (m Map) AfterLoad(fn func()) {
	if m.ds == nil {
		// Not currently decoding.
		m.Failf("not decoding")
	}

	// Queue the local callback; this will execute when all of the above
	// data dependencies have been cleared.
	m.os.callbacks = append(m.os.callbacks, fn)
}
