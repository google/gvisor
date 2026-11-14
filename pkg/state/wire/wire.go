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

// Package wire contains a few basic types that can be composed to serialize
// graph information for the state package. This package defines the wire
// protocol.
//
// These types use value or pointer receivers to implement Object. Pointer
// values fit directly in the interface; scalar values may require boxing when
// returned through Object.
//
// This package also uses panic as control flow, so callers should be careful to
// wrap calls in appropriate handlers.
//
// Testing for this package is driven by the state test package.
package wire

import (
	"fmt"
	"io"
	"math"

	"gvisor.dev/gvisor/pkg/gohacks"
)

// Reader bundles an io.Reader with a buffer used to implement readByte
// efficiently.
type Reader struct {
	io.Reader

	buf [1]byte
}

// readByte reads a single byte from r.Reader without allocation. It panics on
// error.
func (r *Reader) readByte() byte {
	n, err := r.Read(r.buf[:])
	if n != 1 {
		panic(err)
	}
	return r.buf[0]
}

// Writer bundles an io.Writer with a buffer used to implement writeByte
// efficiently.
type Writer struct {
	io.Writer

	// buf is used by Uint as a scratch buffer.
	buf [10]byte
}

// readFull is a utility. The equivalent is not needed for Write, but the API
// contract dictates that it must always complete all bytes given or return an
// error.
func readFull(r *Reader, p []byte) {
	for done := 0; done < len(p); {
		n, err := r.Read(p[done:])
		done += n
		if n == 0 && err != nil {
			panic(err)
		}
	}
}

// Object is a generic object.
type Object interface {
	// save saves the given object.
	//
	// Panic is used for error control flow.
	save(*Writer)
}

// Bool is a boolean.
type Bool bool

// loadBool loads an object of type Bool.
func loadBool(r *Reader) Bool {
	b := loadUint(r)
	return Bool(b == 1)
}

// save implements Object.save.
func (b Bool) save(w *Writer) {
	var v Uint
	if b {
		v = 1
	} else {
		v = 0
	}
	v.save(w)
}

// Int is a signed integer.
//
// This uses varint encoding.
type Int int64

// loadInt loads an object of type Int.
func loadInt(r *Reader) Int {
	u := loadUint(r)
	x := Int(u >> 1)
	if u&1 != 0 {
		x = ^x
	}
	return x
}

// save implements Object.save.
func (i Int) save(w *Writer) {
	u := Uint(i) << 1
	if i < 0 {
		u = ^u
	}
	u.save(w)
}

// Uint is an unsigned integer.
type Uint uint64

// loadUint loads an object of type Uint.
func loadUint(r *Reader) Uint {
	var (
		u Uint
		s uint
	)
	for i := 0; i <= 9; i++ {
		b := r.readByte()
		if b < 0x80 {
			if i == 9 && b > 1 {
				panic("overflow")
			}
			u |= Uint(b) << s
			return u
		}
		u |= Uint(b&0x7f) << s
		s += 7
	}
	panic("unreachable")
}

// save implements Object.save.
func (u Uint) save(w *Writer) {
	i := 0
	for u >= 0x80 {
		w.buf[i] = byte(u) | 0x80
		i++
		u >>= 7
	}
	w.buf[i] = byte(u)
	if _, err := w.Write(w.buf[:i+1]); err != nil {
		panic(err)
	}
}

// Float32 is a 32-bit floating point number.
type Float32 float32

// save implements Object.save.
func (f Float32) save(w *Writer) {
	n := Uint(math.Float32bits(float32(f)))
	n.save(w)
}

// Float64 is a 64-bit floating point number.
type Float64 float64

// save implements Object.save.
func (f Float64) save(w *Writer) {
	n := Uint(math.Float64bits(float64(f)))
	n.save(w)
}

// Complex64 is a 64-bit complex number.
type Complex64 complex128

// save implements Object.save.
func (c *Complex64) save(w *Writer) {
	re := Float32(real(*c))
	im := Float32(imag(*c))
	re.save(w)
	im.save(w)
}

// Complex128 is a 128-bit complex number.
type Complex128 complex128

// save implements Object.save.
func (c *Complex128) save(w *Writer) {
	re := Float64(real(*c))
	im := Float64(imag(*c))
	re.save(w)
	im.save(w)
}

// String is a string.
type String string

// loadString loads an object of type String.
func loadString(r *Reader) String {
	l := loadUint(r)
	p := make([]byte, l) // Escapes: decoded string storage.
	readFull(r, p)
	return String(gohacks.StringFromImmutableBytes(p))
}

// save implements Object.save.
func (s *String) save(w *Writer) {
	l := Uint(len(*s))
	l.save(w)
	p := gohacks.ImmutableBytesFromString(string(*s))
	_, err := w.Write(p) // Must write all bytes.
	if err != nil {
		panic(err)
	}
}

// Dot is a kind of reference: one of Index and FieldName.
type Dot interface {
	isDot()
}

// Index is a reference resolution.
type Index uint32

func (Index) isDot() {}

// FieldName is a reference resolution.
type FieldName string

func (*FieldName) isDot() {}

// Ref is a reference to an object.
type Ref struct {
	// Root is the root object.
	Root Uint

	// Dots is the set of traversals required from the Root object above.
	// Note that this will be stored in reverse order for efficiency.
	Dots []Dot

	// Type is the base type for the root object. This is non-nil iff Dots
	// is non-zero length (that is, this is a complex reference). This is
	// not *strictly* necessary, but can be used to simplify decoding.
	Type TypeSpec
}

// save implements Object.save.
func (r *Ref) save(w *Writer) {
	r.Root.save(w)
	l := Uint(len(r.Dots))
	l.save(w)
	for _, d := range r.Dots {
		// See loadReference. We use non-negative numbers to encode Index
		// objects and negative numbers to encode field lengths.
		switch x := d.(type) {
		case Index:
			i := Int(x)
			i.save(w)
		case *FieldName:
			d := Int(-len(*x))
			d.save(w)
			p := gohacks.ImmutableBytesFromString(string(*x))
			if _, err := w.Write(p); err != nil {
				panic(err)
			}
		default:
			panic("unknown dot implementation")
		}
	}
	if l != 0 {
		// See above.
		saveTypeSpec(w, r.Type)
	}
}

// Nil is a primitive zero value of any type.
type Nil struct{}

// save implements Object.save.
func (Nil) save(w *Writer) {}

// Slice is a slice value.
type Slice struct {
	Length   Uint
	Capacity Uint
	Ref      Ref
}

// save implements Object.save.
func (s *Slice) save(w *Writer) {
	s.Length.save(w)
	s.Capacity.save(w)
	s.Ref.save(w)
}

// ObjectArray is an array of composite elements (structs, interfaces, slices,
// maps, nested arrays, Nil).
type ObjectArray struct {
	arrayKind
	Contents []Object
}

// save implements Object.save.
func (a *ObjectArray) save(w *Writer) {
	l := Uint(len(a.Contents))
	l.save(w)
	if l == 0 {
		// Empty arrays omit their element tag.
		return
	}
	// See above.
	Save(w, a.Contents[0])
	for i := 1; i < int(l); i++ {
		a.Contents[i].save(w)
	}
}

func (a *ObjectArray) Len() int             { return len(a.Contents) }
func (a *ObjectArray) Element(i int) Object { return a.Contents[i] }

// Map is a map value.
type Map struct {
	Keys   []Object
	Values []Object
}

// save implements Object.save.
func (m *Map) save(w *Writer) {
	l := Uint(len(m.Keys))
	if int(l) != len(m.Values) {
		panic(fmt.Sprintf("mismatched keys (%d) and values (%d)", len(m.Keys), len(m.Values))) // Escapes: error formatting.
	}
	l.save(w)
	if l == 0 {
		// Empty maps omit their element tags.
		return
	}
	// See above.
	Save(w, m.Keys[0])
	Save(w, m.Values[0])
	for i := 1; i < int(l); i++ {
		m.Keys[i].save(w)
		m.Values[i].save(w)
	}
}

// TypeSpec is a type dereference.
type TypeSpec interface {
	isTypeSpec()
}

// TypeID is a concrete type ID.
type TypeID Uint

func (TypeID) isTypeSpec() {}

// TypeSpecPointer is a pointer type.
type TypeSpecPointer struct {
	Type TypeSpec
}

func (*TypeSpecPointer) isTypeSpec() {}

// TypeSpecArray is an array type.
type TypeSpecArray struct {
	Count Uint
	Type  TypeSpec
}

func (*TypeSpecArray) isTypeSpec() {}

// TypeSpecSlice is a slice type.
type TypeSpecSlice struct {
	Type TypeSpec
}

func (*TypeSpecSlice) isTypeSpec() {}

// TypeSpecMap is a map type.
type TypeSpecMap struct {
	Key   TypeSpec
	Value TypeSpec
}

func (*TypeSpecMap) isTypeSpec() {}

// TypeSpecNil is an empty type.
type TypeSpecNil struct{}

func (TypeSpecNil) isTypeSpec() {}

// TypeSpec types.
//
// These use a distinct encoding on the wire, as they are used only in the
// interface object. They are decoded through the dedicated loadType and
// saveTypeSpec functions.
const (
	typeSpecTypeID Uint = iota
	typeSpecPointer
	typeSpecArray
	typeSpecSlice
	typeSpecMap
	typeSpecNil
)

// saveTypeSpec saves TypeSpec values.
func saveTypeSpec(w *Writer, t TypeSpec) {
	switch x := t.(type) {
	case TypeID:
		typeSpecTypeID.save(w)
		Uint(x).save(w)
	case *TypeSpecPointer:
		typeSpecPointer.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecArray:
		typeSpecArray.save(w)
		x.Count.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecSlice:
		typeSpecSlice.save(w)
		saveTypeSpec(w, x.Type)
	case *TypeSpecMap:
		typeSpecMap.save(w)
		saveTypeSpec(w, x.Key)
		saveTypeSpec(w, x.Value)
	case TypeSpecNil:
		typeSpecNil.save(w)
	default:
		// This should not happen?
		panic(fmt.Errorf("unknown type %T", t)) // Escapes: error formatting.
	}
}

// Interface is an interface value.
type Interface struct {
	Type  TypeSpec
	Value Object
}

// save implements Object.save.
func (i *Interface) save(w *Writer) {
	saveTypeSpec(w, i.Type)
	Save(w, i.Value)
}

// Type is type information.
type Type struct {
	Name   string
	Fields []string
}

// save implements Object.save.
func (t *Type) save(w *Writer) {
	s := String(t.Name)
	s.save(w)
	l := Uint(len(t.Fields))
	l.save(w)
	for i := 0; i < int(l); i++ {
		s := String(t.Fields[i])
		s.save(w)
	}
}

// multipleObjects is a special type for serializing multiple objects.
type multipleObjects []Object

// save implements Object.save.
func (m *multipleObjects) save(w *Writer) {
	l := Uint(len(*m))
	l.save(w)
	for i := 0; i < int(l); i++ {
		Save(w, (*m)[i])
	}
}

// noObjects represents no objects.
type noObjects struct{}

// save implements Object.save.
func (noObjects) save(w *Writer) {}

// Struct is a basic composite value.
type Struct struct {
	TypeID TypeID
	fields Object // Optionally noObjects or *multipleObjects.
}

// Field returns a pointer to the given field slot.
//
// This must be called after Alloc.
func (s *Struct) Field(i int) *Object {
	if fields, ok := s.fields.(*multipleObjects); ok {
		return &((*fields)[i])
	}
	if _, ok := s.fields.(noObjects); ok {
		// Alloc may be optionally called; can't call twice.
		panic("Field called inappropriately, wrong Alloc?")
	}
	return &s.fields
}

// Alloc allocates the given number of fields.
//
// This must be called before Add and Save.
//
// Precondition: slots must be positive.
func (s *Struct) Alloc(slots int) {
	switch {
	case slots == 0:
		s.fields = noObjects{}
	case slots == 1:
		// Leave it alone.
	case slots > 1:
		fields := make(multipleObjects, slots)
		s.fields = &fields
	default:
		// Violates precondition.
		panic(fmt.Sprintf("Alloc called with negative slots %d?", slots))
	}
}

// Fields returns the number of fields.
func (s *Struct) Fields() int {
	switch x := s.fields.(type) {
	case *multipleObjects:
		return len(*x)
	case noObjects:
		return 0
	default:
		return 1
	}
}

// save implements Object.save.
//
// Precondition: Alloc must have been called, and the fields all filled in
// appropriately. See Alloc and Add for more details.
func (s *Struct) save(w *Writer) {
	Uint(s.TypeID).save(w)
	Save(w, s.fields)
}

// Object types.
//
// N.B. Be careful about changing the order or introducing new elements in the
// middle here. This is part of the wire format and shouldn't change.
const (
	typeBool Uint = iota
	typeInt
	typeUint
	typeFloat32
	typeFloat64
	typeNil
	typeRef
	typeString
	typeSlice
	typeArray
	typeMap
	typeStruct
	typeNoObjects
	typeMultipleObjects
	typeInterface
	typeComplex64
	typeComplex128
	typeType
)

// Save saves the given object.
//
// +checkescape:hard
//
// N.B. This function will panic on error.
func Save(w *Writer, obj Object) {
	switch x := obj.(type) {
	case Bool:
		typeBool.save(w)
		x.save(w)
	case Int:
		typeInt.save(w)
		x.save(w)
	case Uint:
		typeUint.save(w)
		x.save(w)
	case Float32:
		typeFloat32.save(w)
		x.save(w)
	case Float64:
		typeFloat64.save(w)
		x.save(w)
	case Nil:
		typeNil.save(w)
		x.save(w)
	case *Ref:
		typeRef.save(w)
		x.save(w)
	case *String:
		typeString.save(w)
		x.save(w)
	case *Slice:
		typeSlice.save(w)
		x.save(w)
	case Array:
		typeArray.save(w)
		x.save(w)
	case *Map:
		typeMap.save(w)
		x.save(w)
	case *Struct:
		typeStruct.save(w)
		x.save(w)
	case noObjects:
		typeNoObjects.save(w)
		x.save(w)
	case *multipleObjects:
		typeMultipleObjects.save(w)
		x.save(w)
	case *Interface:
		typeInterface.save(w)
		x.save(w)
	case *Type:
		typeType.save(w)
		x.save(w)
	case *Complex64:
		typeComplex64.save(w)
		x.save(w)
	case *Complex128:
		typeComplex128.save(w)
		x.save(w)
	default:
		panic(fmt.Errorf("unknown type: %#v", obj)) // Escapes: error formatting.
	}
}

// LoadUint loads a single unsigned integer.
//
// N.B. This function will panic on error.
func LoadUint(r *Reader) uint64 {
	return uint64(loadUint(r))
}

// SaveUint saves a single unsigned integer.
//
// N.B. This function will panic on error.
func SaveUint(w *Writer, v uint64) {
	Uint(v).save(w)
}
