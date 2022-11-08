// Copyright 2019 The gVisor Authors.
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

// Package analysis implements common functionality used by generated
// go_marshal tests.
package analysis

// All functions in this package are unsafe and are not intended for general
// consumption. They contain sharp edge cases and the caller is responsible for
// ensuring none of them are hit. Callers must be carefully to pass in only sane
// arguments. Failure to do so may cause panics at best and arbitrary memory
// corruption at worst.
//
// Never use outside of tests.

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"unsafe"
)

// RandomizeValue assigns random value(s) to an abitrary type. This is intended
// for used with ABI structs from go_marshal, meaning the typical restrictions
// apply (fixed-size types, no pointers, maps, channels, etc), and should only
// be used on zeroed values to avoid overwriting pointers to active go objects.
//
// Internally, we populate the type with random data by doing an unsafe cast to
// access the underlying memory of the type and filling it as if it were a byte
// slice. This almost gets us what we want, but padding fields named "_" are
// normally not accessible, so we walk the type and recursively zero all "_"
// fields.
//
// Precondition: x must be a pointer. x must not contain any valid
// pointers to active go objects (pointer fields aren't allowed in ABI
// structs anyways), or we'd be violating the go runtime contract and
// the GC may malfunction.
func RandomizeValue(x any) {
	v := reflect.Indirect(reflect.ValueOf(x))
	if !v.CanSet() {
		panic("RandomizeType() called with an unaddressable value. You probably need to pass a pointer to the argument")
	}

	// Cast the underlying memory for the type into a byte slice.
	var b []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	// Note: v.UnsafeAddr panics if x is passed by value. x should be a pointer.
	hdr.Data = v.UnsafeAddr()
	hdr.Len = int(v.Type().Size())
	hdr.Cap = hdr.Len

	// Fill the byte slice with random data, which in effect fills the type with
	// random values.
	n, err := rand.Read(b)
	if err != nil || n != len(b) {
		panic("unreachable")
	}

	// Normally, padding fields are not accessible, so zero them out.
	reflectZeroPaddingFields(v.Type(), b, false)
}

// reflectZeroPaddingFields assigns zero values to padding fields for the value
// of type r, represented by the memory in data. Padding fields are defined as
// fields with the name "_". If zero is true, the immediate value itself is
// zeroed. In addition, the type is recursively scanned for padding fields in
// inner types.
//
// This is used for zeroing padding fields after calling RandomizeValue.
func reflectZeroPaddingFields(r reflect.Type, data []byte, zero bool) {
	if zero {
		for i := range data {
			data[i] = 0
		}
	}
	switch r.Kind() {
	case reflect.Int8, reflect.Uint8, reflect.Int16, reflect.Uint16, reflect.Int32, reflect.Uint32, reflect.Int64, reflect.Uint64:
		// These types are explicitly allowed in an ABI type, but we don't need
		// to recurse further as they're scalar types.
	case reflect.Struct:
		for i, numFields := 0, r.NumField(); i < numFields; i++ {
			f := r.Field(i)
			off := f.Offset
			len := f.Type.Size()
			window := data[off : off+len]
			reflectZeroPaddingFields(f.Type, window, f.Name == "_")
		}
	case reflect.Array:
		eLen := int(r.Elem().Size())
		if int(r.Size()) != eLen*r.Len() {
			panic("Array has unexpected size?")
		}
		for i, n := 0, r.Len(); i < n; i++ {
			reflectZeroPaddingFields(r.Elem(), data[i*eLen:(i+1)*eLen], false)
		}
	default:
		panic(fmt.Sprintf("Type %v not allowed in ABI struct", r.Kind()))

	}
}

// AlignmentCheck ensures the definition of the type represented by typ doesn't
// cause the go compiler to emit implicit padding between elements of the type
// (i.e. fields in a struct).
//
// AlignmentCheck doesn't explicitly recurse for embedded structs because any
// struct present in an ABI struct must also be Marshallable, and therefore
// they're aligned by definition (or their alignment check would have failed).
func AlignmentCheck(t *testing.T, typ reflect.Type) (ok bool, delta uint64) {
	switch typ.Kind() {
	case reflect.Int8, reflect.Uint8, reflect.Int16, reflect.Uint16, reflect.Int32, reflect.Uint32, reflect.Int64, reflect.Uint64:
		// Primitive types are always considered well aligned. Primitive types
		// that are fields in structs are checked independently, this branch
		// exists to handle recursive calls to alignmentCheck.
	case reflect.Struct:
		xOff := 0
		nextXOff := 0
		skipNext := false
		for i, numFields := 0, typ.NumField(); i < numFields; i++ {
			xOff = nextXOff
			f := typ.Field(i)
			fmt.Printf("Checking alignment of %s.%s @ %d [+%d]...\n", typ.Name(), f.Name, f.Offset, f.Type.Size())
			nextXOff = int(f.Offset + f.Type.Size())

			if f.Name == "_" {
				// Padding fields need not be aligned.
				fmt.Printf("Padding field of type %v\n", f.Type)
				continue
			}

			if tag, ok := f.Tag.Lookup("marshal"); ok && tag == "unaligned" {
				skipNext = true
				continue
			}

			if skipNext {
				skipNext = false
				fmt.Printf("Skipping alignment check for field %s.%s explicitly marked as unaligned.\n", typ.Name(), f.Name)
				continue
			}

			if xOff != int(f.Offset) {
				implicitPad := int(f.Offset) - xOff
				t.Fatalf("Suspect offset for field %s.%s, detected an implicit %d byte padding from offset %d to %d; either add %d bytes of explicit padding before this field or tag it as `marshal:\"unaligned\"`.", typ.Name(), f.Name, implicitPad, xOff, f.Offset, implicitPad)
			}
		}

		// Ensure structs end on a byte explicitly defined by the type.
		if typ.NumField() > 0 && nextXOff != int(typ.Size()) {
			implicitPad := int(typ.Size()) - nextXOff
			f := typ.Field(typ.NumField() - 1) // Final field
			if tag, ok := f.Tag.Lookup("marshal"); ok && tag == "unaligned" {
				// Final field explicitly marked unaligned.
				break
			}
			t.Fatalf("Suspect offset for field %s.%s at the end of %s, detected an implicit %d byte padding from offset %d to %d at the end of the struct; either add %d bytes of explict padding at end of the struct or tag the final field %s as `marshal:\"unaligned\"`.",
				typ.Name(), f.Name, typ.Name(), implicitPad, nextXOff, typ.Size(), implicitPad, f.Name)
		}
	case reflect.Array:
		// Independent arrays are also always considered well aligned. We only
		// need to worry about their alignment when they're embedded in structs,
		// which we handle above.
	default:
		t.Fatalf("Unsupported type in ABI struct while checking for field alignment for type: %v", typ.Kind())
	}
	return true, uint64(typ.Size())
}
