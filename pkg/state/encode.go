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

package state

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"

	"github.com/golang/protobuf/proto"
	pb "gvisor.googlesource.com/gvisor/pkg/state/object_go_proto"
)

// queuedObject is an object queued for encoding.
type queuedObject struct {
	id   uint64
	obj  reflect.Value
	path recoverable
}

// encodeState is state used for encoding.
//
// The encoding process is a breadth-first traversal of the object graph. The
// inherent races and dependencies are much simpler than the decode case.
type encodeState struct {
	// lastID is the last object ID.
	//
	// See idsByObject for context. Because of the special zero encoding
	// used for reference values, the first ID must be 1.
	lastID uint64

	// idsByObject is a set of objects, indexed via:
	//
	//	reflect.ValueOf(x).UnsafeAddr
	//
	// This provides IDs for objects.
	idsByObject map[uintptr]uint64

	// values stores values that span the addresses.
	//
	// addrSet is a a generated type which efficiently stores ranges of
	// addresses. When encoding pointers, these ranges are filled in and
	// used to check for overlapping or conflicting pointers. This would
	// indicate a pointer to an field, or a non-type safe value, neither of
	// which are currently decodable.
	//
	// See the usage of values below for more context.
	values addrSet

	// w is the output stream.
	w io.Writer

	// pending is the list of objects to be serialized.
	//
	// This is a set of queuedObjects.
	pending list.List

	// done is the a list of finished objects.
	//
	// This is kept to prevent garbage collection and address reuse.
	done list.List

	// stats is the passed stats object.
	stats *Stats

	// recoverable is the panic recover facility.
	recoverable
}

// register looks up an ID, registering if necessary.
//
// If the object was not previosly registered, it is enqueued to be serialized.
// See the documentation for idsByObject for more information.
func (es *encodeState) register(obj reflect.Value) uint64 {
	// It is not legal to call register for any non-pointer objects (see
	// below), so we panic with a recoverable error if this is a mismatch.
	if obj.Kind() != reflect.Ptr && obj.Kind() != reflect.Map {
		panic(fmt.Errorf("non-pointer %#v registered", obj.Interface()))
	}

	addr := obj.Pointer()
	if obj.Kind() == reflect.Ptr && obj.Elem().Type().Size() == 0 {
		// For zero-sized objects, we always provide a unique ID.
		// That's because the runtime internally multiplexes pointers
		// to the same address. We can't be certain what the intent is
		// with pointers to zero-sized objects, so we just give them
		// all unique identities.
	} else if id, ok := es.idsByObject[addr]; ok {
		// Already registered.
		return id
	}

	// Ensure that the first ID given out is one. See note on lastID. The
	// ID zero is used to indicate nil values.
	es.lastID++
	id := es.lastID
	es.idsByObject[addr] = id
	if obj.Kind() == reflect.Ptr {
		// Dereference and treat as a pointer.
		es.pending.PushBack(queuedObject{id: id, obj: obj.Elem(), path: es.recoverable.copy()})

		// Register this object at all addresses.
		typ := obj.Elem().Type()
		if size := typ.Size(); size > 0 {
			r := addrRange{addr, addr + size}
			if !es.values.IsEmptyRange(r) {
				panic(fmt.Errorf("overlapping objects: [new object] %#v [existing object] %#v", obj.Interface(), es.values.FindSegment(addr).Value().Elem().Interface()))
			}
			es.values.Add(r, obj)
		}
	} else {
		// Push back the map itself; when maps are encoded from the
		// top-level, forceMap will be equal to true.
		es.pending.PushBack(queuedObject{id: id, obj: obj, path: es.recoverable.copy()})
	}

	return id
}

// encodeMap encodes a map.
func (es *encodeState) encodeMap(obj reflect.Value) *pb.Map {
	var (
		keys   []*pb.Object
		values []*pb.Object
	)
	for i, k := range obj.MapKeys() {
		v := obj.MapIndex(k)
		kp := es.encodeObject(k, false, ".(key %d)", i)
		vp := es.encodeObject(v, false, "[%#v]", k.Interface())
		keys = append(keys, kp)
		values = append(values, vp)
	}
	return &pb.Map{Keys: keys, Values: values}
}

// encodeStruct encodes a composite object.
func (es *encodeState) encodeStruct(obj reflect.Value) *pb.Struct {
	// Invoke the save.
	m := Map{newInternalMap(es, nil, nil)}
	defer internalMapPool.Put(m.internalMap)
	if !obj.CanAddr() {
		// Force it to a * type of the above; this involves a copy.
		localObj := reflect.New(obj.Type())
		localObj.Elem().Set(obj)
		obj = localObj.Elem()
	}
	fns, ok := registeredTypes.lookupFns(obj.Addr().Type())
	if ok {
		// Invoke the provided saver.
		fns.invokeSave(obj.Addr(), m)
	} else if obj.NumField() == 0 {
		// Allow unregistered anonymous, empty structs.
		return &pb.Struct{}
	} else {
		// Propagate an error.
		panic(fmt.Errorf("unregistered type %T", obj.Interface()))
	}

	// Sort the underlying slice, and check for duplicates. This is done
	// once instead of on each add, because performing this sort once is
	// far more efficient.
	if len(m.data) > 1 {
		sort.Slice(m.data, func(i, j int) bool {
			return m.data[i].name < m.data[j].name
		})
		for i := range m.data {
			if i > 0 && m.data[i-1].name == m.data[i].name {
				panic(fmt.Errorf("duplicate name %s", m.data[i].name))
			}
		}
	}

	// Encode the resulting fields.
	fields := make([]*pb.Field, 0, len(m.data))
	for _, e := range m.data {
		fields = append(fields, &pb.Field{
			Name:  e.name,
			Value: e.object,
		})
	}

	// Return the encoded object.
	return &pb.Struct{Fields: fields}
}

// encodeArray encodes an array.
func (es *encodeState) encodeArray(obj reflect.Value) *pb.Array {
	var (
		contents []*pb.Object
	)
	for i := 0; i < obj.Len(); i++ {
		entry := es.encodeObject(obj.Index(i), false, "[%d]", i)
		contents = append(contents, entry)
	}
	return &pb.Array{Contents: contents}
}

// encodeInterface encodes an interface.
//
// Precondition: the value is not nil.
func (es *encodeState) encodeInterface(obj reflect.Value) *pb.Interface {
	// Check for the nil interface.
	obj = reflect.ValueOf(obj.Interface())
	if !obj.IsValid() {
		return &pb.Interface{
			Type:  "", // left alone in decode.
			Value: &pb.Object{Value: &pb.Object_RefValue{0}},
		}
	}
	// We have an interface value here. How do we save that? We
	// resolve the underlying type and save it as a dispatchable.
	typName, ok := registeredTypes.lookupName(obj.Type())
	if !ok {
		panic(fmt.Errorf("type %s is not registered", obj.Type()))
	}

	// Encode the object again.
	return &pb.Interface{
		Type:  typName,
		Value: es.encodeObject(obj, false, ".(%s)", typName),
	}
}

// encodeObject encodes an object.
//
// If mapAsValue is true, then a map will be encoded directly.
func (es *encodeState) encodeObject(obj reflect.Value, mapAsValue bool, format string, param interface{}) (object *pb.Object) {
	es.push(false, format, param)
	es.stats.Start(obj)

	switch obj.Kind() {
	case reflect.Bool:
		object = &pb.Object{Value: &pb.Object_BoolValue{obj.Bool()}}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		object = &pb.Object{Value: &pb.Object_Int64Value{obj.Int()}}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		object = &pb.Object{Value: &pb.Object_Uint64Value{obj.Uint()}}
	case reflect.Float32, reflect.Float64:
		object = &pb.Object{Value: &pb.Object_DoubleValue{obj.Float()}}
	case reflect.Array:
		switch obj.Type().Elem().Kind() {
		case reflect.Uint8:
			object = &pb.Object{Value: &pb.Object_ByteArrayValue{pbSlice(obj).Interface().([]byte)}}
		case reflect.Uint16:
			// 16-bit slices are serialized as 32-bit slices.
			// See object.proto for details.
			s := pbSlice(obj).Interface().([]uint16)
			t := make([]uint32, len(s))
			for i := range s {
				t[i] = uint32(s[i])
			}
			object = &pb.Object{Value: &pb.Object_Uint16ArrayValue{&pb.Uint16S{Values: t}}}
		case reflect.Uint32:
			object = &pb.Object{Value: &pb.Object_Uint32ArrayValue{&pb.Uint32S{Values: pbSlice(obj).Interface().([]uint32)}}}
		case reflect.Uint64:
			object = &pb.Object{Value: &pb.Object_Uint64ArrayValue{&pb.Uint64S{Values: pbSlice(obj).Interface().([]uint64)}}}
		case reflect.Uintptr:
			object = &pb.Object{Value: &pb.Object_UintptrArrayValue{&pb.Uintptrs{Values: pbSlice(obj).Interface().([]uint64)}}}
		case reflect.Int8:
			object = &pb.Object{Value: &pb.Object_Int8ArrayValue{&pb.Int8S{Values: pbSlice(obj).Interface().([]byte)}}}
		case reflect.Int16:
			// 16-bit slices are serialized as 32-bit slices.
			// See object.proto for details.
			s := pbSlice(obj).Interface().([]int16)
			t := make([]int32, len(s))
			for i := range s {
				t[i] = int32(s[i])
			}
			object = &pb.Object{Value: &pb.Object_Int16ArrayValue{&pb.Int16S{Values: t}}}
		case reflect.Int32:
			object = &pb.Object{Value: &pb.Object_Int32ArrayValue{&pb.Int32S{Values: pbSlice(obj).Interface().([]int32)}}}
		case reflect.Int64:
			object = &pb.Object{Value: &pb.Object_Int64ArrayValue{&pb.Int64S{Values: pbSlice(obj).Interface().([]int64)}}}
		case reflect.Bool:
			object = &pb.Object{Value: &pb.Object_BoolArrayValue{&pb.Bools{Values: pbSlice(obj).Interface().([]bool)}}}
		case reflect.Float32:
			object = &pb.Object{Value: &pb.Object_Float32ArrayValue{&pb.Float32S{Values: pbSlice(obj).Interface().([]float32)}}}
		case reflect.Float64:
			object = &pb.Object{Value: &pb.Object_Float64ArrayValue{&pb.Float64S{Values: pbSlice(obj).Interface().([]float64)}}}
		default:
			object = &pb.Object{Value: &pb.Object_ArrayValue{es.encodeArray(obj)}}
		}
	case reflect.Slice:
		if obj.IsNil() || obj.Cap() == 0 {
			// Handled specially in decode; store as nil value.
			object = &pb.Object{Value: &pb.Object_RefValue{0}}
		} else {
			// Serialize a slice as the array plus length and capacity.
			object = &pb.Object{Value: &pb.Object_SliceValue{&pb.Slice{
				Capacity: uint32(obj.Cap()),
				Length:   uint32(obj.Len()),
				RefValue: es.register(arrayFromSlice(obj)),
			}}}
		}
	case reflect.String:
		object = &pb.Object{Value: &pb.Object_StringValue{obj.String()}}
	case reflect.Ptr:
		if obj.IsNil() {
			// Handled specially in decode; store as a nil value.
			object = &pb.Object{Value: &pb.Object_RefValue{0}}
		} else {
			es.push(true /* dereference */, "", nil)
			object = &pb.Object{Value: &pb.Object_RefValue{es.register(obj)}}
			es.pop()
		}
	case reflect.Interface:
		// We don't check for IsNil here, as we want to encode type
		// information. The case of the empty interface (no type, no
		// value) is handled by encodeInteface.
		object = &pb.Object{Value: &pb.Object_InterfaceValue{es.encodeInterface(obj)}}
	case reflect.Struct:
		object = &pb.Object{Value: &pb.Object_StructValue{es.encodeStruct(obj)}}
	case reflect.Map:
		if obj.IsNil() {
			// Handled specially in decode; store as a nil value.
			object = &pb.Object{Value: &pb.Object_RefValue{0}}
		} else if mapAsValue {
			// Encode the map directly.
			object = &pb.Object{Value: &pb.Object_MapValue{es.encodeMap(obj)}}
		} else {
			// Encode a reference to the map.
			object = &pb.Object{Value: &pb.Object_RefValue{es.register(obj)}}
		}
	default:
		panic(fmt.Errorf("unknown primitive %#v", obj.Interface()))
	}

	es.stats.Done()
	es.pop()
	return
}

// Serialize serializes the object state.
//
// This function may panic and should be run in safely().
func (es *encodeState) Serialize(obj reflect.Value) {
	es.register(obj.Addr())

	// Pop off the list until we're done.
	for es.pending.Len() > 0 {
		e := es.pending.Front()
		es.pending.Remove(e)

		// Extract the queued object.
		qo := e.Value.(queuedObject)
		es.from = &qo.path
		o := es.encodeObject(qo.obj, true, "", nil)

		// Emit to our output stream.
		if err := es.writeObject(qo.id, o); err != nil {
			panic(err)
		}

		// Mark as done.
		es.done.PushBack(e)
	}

	// Write a zero-length terminal at the end; this is a sanity check
	// applied at decode time as well (see decode.go).
	if err := WriteHeader(es.w, 0, false); err != nil {
		panic(err)
	}
}

// WriteHeader writes a header.
//
// Each object written to the statefile should be prefixed with a header. In
// order to generate statefiles that play nicely with debugging tools, raw
// writes should be prefixed with a header with object set to false and the
// appropriate length. This will allow tools to skip these regions.
func WriteHeader(w io.Writer, length uint64, object bool) error {
	// The lowest-order bit encodes whether this is a valid object. This is
	// a purely internal convention, but allows the object flag to be
	// returned from ReadHeader.
	length = length << 1
	if object {
		length |= 0x1
	}

	// Write a header.
	var hdr [32]byte
	encodedLen := binary.PutUvarint(hdr[:], length)
	for done := 0; done < encodedLen; {
		n, err := w.Write(hdr[done:encodedLen])
		done += n
		if n == 0 && err != nil {
			return err
		}
	}

	return nil
}

// writeObject writes an object to the stream.
func (es *encodeState) writeObject(id uint64, obj *pb.Object) error {
	// Marshal the proto.
	buf, err := proto.Marshal(obj)
	if err != nil {
		return err
	}

	// Write the object header.
	if err := WriteHeader(es.w, uint64(len(buf)), true); err != nil {
		return err
	}

	// Write the object.
	for done := 0; done < len(buf); {
		n, err := es.w.Write(buf[done:])
		done += n
		if n == 0 && err != nil {
			return err
		}
	}

	return nil
}

// addrSetFunctions is used by addrSet.
type addrSetFunctions struct{}

func (addrSetFunctions) MinKey() uintptr {
	return 0
}

func (addrSetFunctions) MaxKey() uintptr {
	return ^uintptr(0)
}

func (addrSetFunctions) ClearValue(val *reflect.Value) {
}

func (addrSetFunctions) Merge(_ addrRange, val1 reflect.Value, _ addrRange, val2 reflect.Value) (reflect.Value, bool) {
	return val1, val1 == val2
}

func (addrSetFunctions) Split(_ addrRange, val reflect.Value, _ uintptr) (reflect.Value, reflect.Value) {
	return val, val
}
