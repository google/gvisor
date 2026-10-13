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

package state

import (
	"encoding"
	"reflect"
	"slices"
	"time"

	"gvisor.dev/gvisor/pkg/state/wire"
)

// typeEntry is an entry in the typeDatabase.
type typeEntry struct {
	ID typeID
	wire.Type
}

// reconciledTypeEntry is a reconciled entry in the typeDatabase.
type reconciledTypeEntry struct {
	wire.Type
	LocalType  reflect.Type
	FieldOrder []int
}

// typeEncodeDatabase is an internal TypeInfo database for encoding.
type typeEncodeDatabase struct {
	// byType maps by type to the typeEntry.
	byType map[reflect.Type]*typeEntry

	// lastID is the last used ID.
	lastID typeID
}

// makeTypeEncodeDatabase makes a typeDatabase.
func makeTypeEncodeDatabase() typeEncodeDatabase {
	return typeEncodeDatabase{
		byType: make(map[reflect.Type]*typeEntry),
	}
}

// typeDecodeDatabase is an internal TypeInfo database for decoding.
type typeDecodeDatabase struct {
	// byID maps by ID to type.
	byID []*reconciledTypeEntry

	// pending are entries that are pending validation by Lookup. These
	// will be reconciled with actual objects. Note that these will also be
	// used to lookup types by name, since they may not be reconciled and
	// there's little value to deleting from this map.
	pending []*wire.Type
}

// makeTypeDecodeDatabase makes a typeDatabase.
func makeTypeDecodeDatabase() typeDecodeDatabase {
	return typeDecodeDatabase{}
}

// lookupTypeInfo extracts the metadata for a type.
func lookupTypeInfo(typ reflect.Type) (wire.Type, bool) {
	if info, ok := reverseTypeDatabase[typ]; ok {
		return info, true
	}
	v := reflect.Zero(reflect.PointerTo(typ)).Interface()
	t, ok := v.(Type)
	if !ok {
		// Is this a primitive?
		if typ.Kind() == reflect.Interface {
			return wire.Type{Name: interfaceType}, true
		}
		name := typ.Name()
		if _, ok := primitiveTypeDatabase[name]; !ok {
			// This is not a known type, and not a primitive. The
			// encoder may proceed for anonymous empty structs, or
			// it may deference the type pointer and try again.
			return wire.Type{}, false
		}
		return wire.Type{Name: name}, true
	}
	// Sanity check the type.
	if raceEnabled {
		// Registered types were found above. Preserve the handling of
		// unregistered embedded types and anonymous empty structs.
		return wire.Type{}, false
	}
	return wire.Type{Name: t.StateTypeName(), Fields: t.StateFields()}, true
}

// Lookup looks up or registers the given object.
//
// The bool indicates whether this is an existing entry: false means the entry
// did not exist, and true means the entry did exist. If this bool is false and
// the returned typeEntry are nil, then the obj did not implement the Type
// interface.
func (tdb *typeEncodeDatabase) Lookup(typ reflect.Type) (*typeEntry, bool) {
	te, ok := tdb.byType[typ]
	if !ok {
		// Lookup the type information.
		info, ok := lookupTypeInfo(typ)
		if !ok {
			// Empty structs may still be encoded, so let the
			// caller decide what to do from here.
			return nil, false
		}

		// Register the new type.
		tdb.lastID++
		te = &typeEntry{
			ID:   tdb.lastID,
			Type: info,
		}

		// All done.
		tdb.byType[typ] = te
		return te, false
	}
	return te, true
}

// Register adds a typeID entry.
func (tbd *typeDecodeDatabase) Register(typ *wire.Type) {
	tbd.pending = append(tbd.pending, typ)
}

// LookupName looks up the type name by ID.
func (tbd *typeDecodeDatabase) LookupName(id typeID) string {
	if len(tbd.pending) < int(id) {
		// This is likely an encoder error?
		Failf("type ID %d not available", id)
	}
	return tbd.pending[id-1].Name
}

// LookupType looks up the type by ID.
func (tbd *typeDecodeDatabase) LookupType(id typeID) reflect.Type {
	name := tbd.LookupName(id)
	typ, ok := globalTypeDatabase[name]
	if !ok {
		// If not available, see if it's primitive.
		typ, ok = primitiveTypeDatabase[name]
		if !ok && name == interfaceType {
			// Matches the built-in interface type.
			var i any
			return reflect.TypeOf(&i).Elem()
		}
		if !ok {
			// The type is perhaps not registered?
			Failf("type name %q is not available", name)
		}
		return typ // Primitive type.
	}
	return typ // Registered type.
}

// singleFieldOrder defines the field order for a single field.
var singleFieldOrder = []int{0}

// Lookup looks up or registers the given object.
//
// First, the typeID is searched to see if this has already been appropriately
// reconciled. If no, then a reconciliation will take place that may result in a
// field ordering. If a nil reconciledTypeEntry is returned from this method,
// then the object does not support the Type interface.
//
// This method never returns nil.
func (tbd *typeDecodeDatabase) Lookup(id typeID, typ reflect.Type) *reconciledTypeEntry {
	if len(tbd.byID) >= int(id) && tbd.byID[id-1] != nil {
		// Already reconciled.
		return tbd.byID[id-1]
	}
	// The ID has not been reconciled yet. That's fine. We need to make
	// sure it aligns with the current provided object.
	if len(tbd.pending) < int(id) {
		// This id was never registered. Probably an encoder error?
		Failf("typeDatabase does not contain id %d", id)
	}
	// Extract the pending info.
	pending := tbd.pending[id-1]
	// Grow the byID list.
	if len(tbd.byID) < int(id) {
		tbd.byID = append(tbd.byID, make([]*reconciledTypeEntry, int(id)-len(tbd.byID))...)
	}
	// Reconcile the type.
	info, ok := lookupTypeInfo(typ)
	if !ok {
		// Empty structs are decoded only when the type is nil. Since
		// this isn't the case, we fail here.
		Failf("unsupported type %q during decode; can't reconcile", pending.Name)
	}
	name, fields := info.Name, info.Fields
	if name != pending.Name {
		// Are these the same type? Print a helpful message as this may
		// actually happen in practice if types change.
		Failf("typeDatabase contains conflicting definitions for id %d: %s->%v (current) and %s->%v (existing)",
			id, name, fields, pending.Name, pending.Fields)
	}
	rte := &reconciledTypeEntry{
		Type:      info,
		LocalType: typ,
	}
	// If there are zero or one fields, then we skip allocating the field
	// slice. There is special handling for decoding in this case. If the
	// field name does not match, it will be caught in the general purpose
	// code below.
	if len(fields) != len(pending.Fields) {
		Failf("type %q contains different fields: %v (decode) and %v (encode)",
			name, fields, pending.Fields)
	}
	if len(fields) == 0 {
		tbd.byID[id-1] = rte // Save.
		return rte
	}
	if len(fields) == 1 && fields[0] == pending.Fields[0] {
		tbd.byID[id-1] = rte // Save.
		rte.FieldOrder = singleFieldOrder
		return rte
	}
	// Local field names are unique. Equal lengths and a match for every
	// local name require the wire fields to be a permutation, rejecting
	// missing or duplicate names.
	fieldOrder := make([]int, len(fields))
	for i, name := range fields {
		fieldOrder[i] = -1 // Sentinel.
		// Is it an exact match?
		if pending.Fields[i] == name {
			fieldOrder[i] = i
			continue
		}
		// Find the matching field.
		for j, otherName := range pending.Fields {
			if name == otherName {
				fieldOrder[i] = j
				break
			}
		}
		if fieldOrder[i] == -1 {
			// The type name matches but we are lacking some common fields.
			Failf("type %q has mismatched fields: %v (decode) and %v (encode)",
				name, fields, pending.Fields)
		}
	}
	// The type has been reeconciled.
	rte.FieldOrder = fieldOrder
	tbd.byID[id-1] = rte
	return rte
}

// interfaceType defines all interfaces.
const interfaceType = "interface"

// primitiveTypeDatabase is a set of fixed types.
var primitiveTypeDatabase = func() map[string]reflect.Type {
	r := make(map[string]reflect.Type)
	for _, t := range []reflect.Type{
		reflect.TypeFor[bool](),
		reflect.TypeFor[int](),
		reflect.TypeFor[int8](),
		reflect.TypeFor[int16](),
		reflect.TypeFor[int32](),
		reflect.TypeFor[int64](),
		reflect.TypeFor[uint](),
		reflect.TypeFor[uintptr](),
		reflect.TypeFor[uint8](),
		reflect.TypeFor[uint16](),
		reflect.TypeFor[uint32](),
		reflect.TypeFor[uint64](),
		reflect.TypeFor[string](),
		reflect.TypeFor[float32](),
		reflect.TypeFor[float64](),
		reflect.TypeFor[complex64](),
		reflect.TypeFor[complex128](),
	} {
		r[t.Name()] = t
	}
	return r
}()

// globalTypeDatabase is used for dispatching interfaces on decode.
var globalTypeDatabase = map[string]reflect.Type{}

// reverseTypeDatabase holds immutable metadata indexed by the original type.
var reverseTypeDatabase = map[reflect.Type]wire.Type{}

// Release releases references to global type databases.
// Must only be called in contexts where they will definitely never be used,
// in order to save memory.
func Release() {
	globalTypeDatabase = nil
	reverseTypeDatabase = nil
}

// binaryObject is a value with a self-contained binary representation.
type binaryObject interface {
	encoding.BinaryAppender
	encoding.BinaryUnmarshaler
}

// saveBinary encodes a foreign struct's self-contained representation. Its
// binary codec owns any internal pointer relationships.
func (es *encodeState) saveBinary(value binaryObject, name string, s Sink) {
	data, err := value.AppendBinary(es.binaryBuf[:0])
	es.binaryBuf = data
	if err != nil {
		Failf("encoding %s: %w", name, err)
	}
	// Copy before reusing binaryBuf: wire objects are serialized only after
	// the full graph is encoded. Strings also decode inline, so map keys are
	// complete when decodeMap inserts them into the restored map.
	s.SaveValue(0, string(data))
}

func loadBinary(value binaryObject, name string, s Source) {
	var data string
	s.Load(0, &data)
	if err := value.UnmarshalBinary([]byte(data)); err != nil {
		Failf("decoding %s: %w", name, err)
	}
}

// Register registers a type.
//
// This must be called on init and only done once. Registration lets Load
// reconstruct concrete types held in interfaces without a preceding Save.
func Register(t Type) {
	name := t.StateTypeName()
	fields := t.StateFields()
	typ := reflect.TypeOf(t)
	if raceEnabled {
		// Register must always be called on pointers.
		if typ.Kind() != reflect.Ptr {
			Failf("Register must be called on pointers")
		}
	}
	typ = typ.Elem()
	if raceEnabled {
		if typ.Kind() == reflect.Struct {
			// All registered structs must implement SaverLoader. We allow
			// the registration is non-struct types with just the Type
			// interface, but we need to call StateSave/StateLoad methods
			// on aggregate types.
			if _, ok := t.(SaverLoader); !ok {
				Failf("struct %T does not implement SaverLoader", t)
			}
		} else {
			// Non-structs must not have any fields. We don't support
			// calling StateSave/StateLoad methods on any non-struct types.
			// If custom behavior is required, these types should be
			// wrapped in a structure of some kind.
			if len(fields) != 0 {
				Failf("non-struct %T has non-zero fields %v", t, fields)
			}
			// We don't allow non-structs to implement StateSave/StateLoad
			// methods, because they won't be called and it's confusing.
			if _, ok := t.(SaverLoader); ok {
				Failf("non-struct %T implements SaverLoader", t)
			}
		}
	}
	register(typ, wire.Type{Name: name, Fields: fields})
}

// registerBinary registers a named foreign struct once, retaining its original
// type for fields, map keys and interfaces. value must point to a named struct.
func registerBinary(value binaryObject) {
	typ := reflect.TypeOf(value).Elem()
	register(typ, wire.Type{
		Name:   typ.PkgPath() + "." + typ.Name(),
		Fields: []string{"value"},
	})
}

// register publishes metadata in the existing type databases.
func register(typ reflect.Type, info wire.Type) {
	if info.Name == "" {
		Failf("type has empty name")
	}
	for i, field := range info.Fields {
		if field == "" {
			Failf("field has empty name for type %q", info.Name)
		}
		if slices.Contains(info.Fields[:i], field) {
			Failf("duplicate field %q for type %s", field, info.Name)
		}
	}
	if raceEnabled {
		if _, ok := primitiveTypeDatabase[info.Name]; ok {
			Failf("conflicting primitiveTypeDatabase entry for %v: used by primitive", typ)
		}
		if _, ok := globalTypeDatabase[info.Name]; ok {
			Failf("conflicting globalTypeDatabase entries for %v: name conflict", typ)
		}
		if info.Name == interfaceType {
			Failf("conflicting name for %v: matches interfaceType", typ)
		}
	}
	globalTypeDatabase[info.Name] = typ
	reverseTypeDatabase[typ] = info
}

func init() {
	registerBinary((*time.Time)(nil))
}
