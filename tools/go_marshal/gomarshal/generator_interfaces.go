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

package gomarshal

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// interfaceGenerator generates marshalling interfaces for a single type.
//
// getState is not thread-safe.
type interfaceGenerator struct {
	sourceBuffer

	// The type we're serializing.
	t *ast.TypeSpec

	// Receiver argument for generated methods.
	r string

	// FileSet containing the tokens for the type we're processing.
	f *token.FileSet

	// is records external packages referenced by the generated implementation.
	is map[string]struct{}

	// ms records Marshallable types referenced by the generated implementation
	// of t's interfaces.
	ms map[string]struct{}

	// as records fields in t that are potentially not packed. The key is the
	// accessor for the field.
	as map[string]struct{}
}

// typeName returns the name of the type this g represents.
func (g *interfaceGenerator) typeName() string {
	return g.t.Name.Name
}

// newinterfaceGenerator creates a new interface generator.
func newInterfaceGenerator(t *ast.TypeSpec, r string, fset *token.FileSet) *interfaceGenerator {
	g := &interfaceGenerator{
		t:  t,
		r:  r,
		f:  fset,
		is: make(map[string]struct{}),
		ms: make(map[string]struct{}),
		as: make(map[string]struct{}),
	}
	g.recordUsedMarshallable(g.typeName())
	return g
}

func (g *interfaceGenerator) recordUsedMarshallable(m string) {
	g.ms[m] = struct{}{}

}

func (g *interfaceGenerator) recordUsedImport(i string) {
	g.is[i] = struct{}{}
}

func (g *interfaceGenerator) recordPotentiallyNonPackedField(fieldName string) {
	g.as[fieldName] = struct{}{}
}

// abortAt aborts the go_marshal tool with the given error message, with a
// reference position to the input source. Same as abortAt, but uses g to
// resolve p to position.
func (g *interfaceGenerator) abortAt(p token.Pos, msg string) {
	abortAt(g.f.Position(p), msg)
}

// scalarSize returns the size of type identified by t. If t isn't a primitive
// type, the size isn't known at code generation time, and must be resolved via
// the marshal.Marshallable interface.
func (g *interfaceGenerator) scalarSize(t *ast.Ident) (size int, unknownSize bool) {
	switch t.Name {
	case "int8", "uint8", "byte":
		return 1, false
	case "int16", "uint16":
		return 2, false
	case "int32", "uint32":
		return 4, false
	case "int64", "uint64":
		return 8, false
	default:
		return 0, true
	}
}

func (g *interfaceGenerator) shift(bufVar string, n int) {
	g.emit("%s = %s[%d:]\n", bufVar, bufVar, n)
}

func (g *interfaceGenerator) shiftDynamic(bufVar, name string) {
	g.emit("%s = %s[%s.SizeBytes():]\n", bufVar, bufVar, name)
}

// marshalScalar writes a single scalar to a byte slice.
func (g *interfaceGenerator) marshalScalar(accessor, typ, bufVar string) {
	switch typ {
	case "int8", "uint8", "byte":
		g.emit("%s[0] = byte(%s)\n", bufVar, accessor)
		g.shift(bufVar, 1)
	case "int16", "uint16":
		g.recordUsedImport("hostarch")
		g.emit("hostarch.ByteOrder.PutUint16(%s[:2], uint16(%s))\n", bufVar, accessor)
		g.shift(bufVar, 2)
	case "int32", "uint32":
		g.recordUsedImport("hostarch")
		g.emit("hostarch.ByteOrder.PutUint32(%s[:4], uint32(%s))\n", bufVar, accessor)
		g.shift(bufVar, 4)
	case "int64", "uint64":
		g.recordUsedImport("hostarch")
		g.emit("hostarch.ByteOrder.PutUint64(%s[:8], uint64(%s))\n", bufVar, accessor)
		g.shift(bufVar, 8)
	default:
		g.emit("%s = %s.MarshalUnsafe(%s)\n", bufVar, accessor, bufVar)
	}
}

// unmarshalScalar reads a single scalar from a byte slice.
func (g *interfaceGenerator) unmarshalScalar(accessor, typ, bufVar string) {
	switch typ {
	case "byte":
		g.emit("%s = %s[0]\n", accessor, bufVar)
		g.shift(bufVar, 1)
	case "int8", "uint8":
		g.emit("%s = %s(%s[0])\n", accessor, typ, bufVar)
		g.shift(bufVar, 1)
	case "int16", "uint16":
		g.recordUsedImport("hostarch")
		g.emit("%s = %s(hostarch.ByteOrder.Uint16(%s[:2]))\n", accessor, typ, bufVar)
		g.shift(bufVar, 2)
	case "int32", "uint32":
		g.recordUsedImport("hostarch")
		g.emit("%s = %s(hostarch.ByteOrder.Uint32(%s[:4]))\n", accessor, typ, bufVar)
		g.shift(bufVar, 4)
	case "int64", "uint64":
		g.recordUsedImport("hostarch")
		g.emit("%s = %s(hostarch.ByteOrder.Uint64(%s[:8]))\n", accessor, typ, bufVar)
		g.shift(bufVar, 8)
	default:
		g.emit("%s = %s.UnmarshalUnsafe(%s)\n", bufVar, accessor, bufVar)
		g.recordPotentiallyNonPackedField(accessor)
	}
}

// emitCastToByteSlice unsafely casts an arbitrary type's underlying memory to a
// byte slice, bypassing escape analysis. The caller is responsible for ensuring
// srcPtr lives until they're done with dstVar, the runtime does not consider
// dstVar dependent on srcPtr due to the escape analysis bypass.
//
// srcPtr must be a pointer.
//
// This function uses internally uses the identifier "hdr", and cannot be used
// in a context where it is already bound.
func (g *interfaceGenerator) emitCastToByteSlice(srcPtr, dstVar, lenExpr string) {
	g.recordUsedImport("gohacks")
	g.emit("// Construct a slice backed by dst's underlying memory.\n")
	g.emit("var %s []byte\n", dstVar)
	g.emit("hdr := (*reflect.SliceHeader)(unsafe.Pointer(&%s))\n", dstVar)
	g.emit("hdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(%s)))\n", srcPtr)
	g.emit("hdr.Len = %s\n", lenExpr)
	g.emit("hdr.Cap = %s\n\n", lenExpr)
}

// emitCastToByteSlice unsafely casts a slice with elements of an abitrary type
// to a byte slice. As part of the cast, the byte slice is made to look
// independent of the src slice by bypassing escape analysis. This means the
// byte slice can be used without causing the source to escape. The caller is
// responsible for ensuring srcPtr lives until they're done with dstVar, as the
// runtime no longer considers dstVar dependent on srcPtr and is free to GC it.
//
// srcPtr must be a pointer.
//
// This function uses internally uses the identifiers "ptr", "val" and "hdr",
// and cannot be used in a context where these identifiers are already bound.
func (g *interfaceGenerator) emitCastSliceToByteSlice(srcPtr, dstVar, lenExpr string) {
	g.emitNoEscapeSliceDataPointer(srcPtr, "val")

	g.emit("// Construct a slice backed by dst's underlying memory.\n")
	g.emit("var %s []byte\n", dstVar)
	g.emit("hdr := (*reflect.SliceHeader)(unsafe.Pointer(&%s))\n", dstVar)
	g.emit("hdr.Data = uintptr(val)\n")
	g.emit("hdr.Len = %s\n", lenExpr)
	g.emit("hdr.Cap = %s\n\n", lenExpr)
}

// emitNoEscapeSliceDataPointer unsafely casts a slice's data pointer to an
// unsafe.Pointer, bypassing escape analysis. The caller is responsible for
// ensuring srcPtr lives until they're done with dstVar, as the runtime no
// longer considers dstVar dependent on srcPtr and is free to GC it.
//
// srcPtr must be a pointer.
//
// This function uses internally uses the identifier "ptr" cannot be used in a
// context where this identifier is already bound.
func (g *interfaceGenerator) emitNoEscapeSliceDataPointer(srcPtr, dstVar string) {
	g.recordUsedImport("gohacks")
	g.emit("ptr := unsafe.Pointer(%s)\n", srcPtr)
	g.emit("%s := gohacks.Noescape(unsafe.Pointer((*reflect.SliceHeader)(ptr).Data))\n\n", dstVar)
}

func (g *interfaceGenerator) emitKeepAlive(ptrVar string) {
	g.emit("// Since we bypassed the compiler's escape analysis, indicate that %s\n", ptrVar)
	g.emit("// must live until the use above.\n")
	g.emit("runtime.KeepAlive(%s) // escapes: replaced by intrinsic.\n", ptrVar)
}

func (g *interfaceGenerator) expandBinaryExpr(b *strings.Builder, e *ast.BinaryExpr) {
	switch x := e.X.(type) {
	case *ast.BinaryExpr:
		// Recursively expand sub-expression.
		g.expandBinaryExpr(b, x)
	case *ast.Ident:
		fmt.Fprintf(b, "%s", x.Name)
	case *ast.BasicLit:
		fmt.Fprintf(b, "%s", x.Value)
	default:
		g.abortAt(e.Pos(), "Cannot convert binary expression to output code. Go-marshal currently only handles simple expressions of literals, constants and basic identifiers")
	}

	fmt.Fprintf(b, "%s", e.Op)

	switch y := e.Y.(type) {
	case *ast.BinaryExpr:
		// Recursively expand sub-expression.
		g.expandBinaryExpr(b, y)
	case *ast.Ident:
		fmt.Fprintf(b, "%s", y.Name)
	case *ast.BasicLit:
		fmt.Fprintf(b, "%s", y.Value)
	default:
		g.abortAt(e.Pos(), "Cannot convert binary expression to output code. Go-marshal currently only handles simple expressions of literals, constants and basic identifiers")
	}
}

// arrayLenExpr returns a string containing a valid golang expression
// representing the length of array a. The returned expression should be treated
// as a single value, and will be already parenthesized as required.
func (g *interfaceGenerator) arrayLenExpr(a *ast.ArrayType) string {
	var b strings.Builder

	switch l := a.Len.(type) {
	case *ast.Ident:
		fmt.Fprintf(&b, "%s", l.Name)
	case *ast.BasicLit:
		fmt.Fprintf(&b, "%s", l.Value)
	case *ast.BinaryExpr:
		g.expandBinaryExpr(&b, l)
		return fmt.Sprintf("(%s)", b.String())
	default:
		g.abortAt(l.Pos(), "Cannot convert this array len expression to output code. Go-marshal currently only handles simple expressions of literals, constants and basic identifiers")
	}
	return b.String()
}
