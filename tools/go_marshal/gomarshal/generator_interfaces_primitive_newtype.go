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

// This file contains the bits of the code generator specific to marshalling
// newtypes on primitives.

package gomarshal

import (
	"fmt"
	"go/ast"
)

// marshalPrimitiveScalar writes a single primitive variable to a byte
// slice.
func (g *interfaceGenerator) marshalPrimitiveScalar(accessor, typ, bufVar string) {
	switch typ {
	case "int8", "uint8", "byte":
		g.emit("%s[0] = byte(*%s)\n", bufVar, accessor)
	case "int16", "uint16":
		g.recordUsedImport("hostarch")
		g.emit("hostarch.ByteOrder.PutUint16(%s[:2], uint16(*%s))\n", bufVar, accessor)
	case "int32", "uint32":
		g.recordUsedImport("hostarch")
		g.emit("hostarch.ByteOrder.PutUint32(%s[:4], uint32(*%s))\n", bufVar, accessor)
	case "int64", "uint64":
		g.recordUsedImport("hostarch")
		g.emit("hostarch.ByteOrder.PutUint64(%s[:8], uint64(*%s))\n", bufVar, accessor)
	default:
		g.emit("// Explicilty cast to the underlying type before dispatching to\n")
		g.emit("// MarshalBytes, so we don't recursively call %s.MarshalBytes\n", accessor)
		g.emit("inner := (*%s)(%s)\n", typ, accessor)
		g.emit("inner.MarshalBytes(%s[:%s.SizeBytes()])\n", bufVar, accessor)
	}
}

// unmarshalPrimitiveScalar read a single primitive variable from a byte slice.
func (g *interfaceGenerator) unmarshalPrimitiveScalar(accessor, typ, bufVar, typeCast string) {
	switch typ {
	case "byte":
		g.emit("*%s = %s(%s[0])\n", accessor, typeCast, bufVar)
	case "int8", "uint8":
		g.emit("*%s = %s(%s(%s[0]))\n", accessor, typeCast, typ, bufVar)
	case "int16", "uint16":
		g.recordUsedImport("hostarch")
		g.emit("*%s = %s(%s(hostarch.ByteOrder.Uint16(%s[:2])))\n", accessor, typeCast, typ, bufVar)
	case "int32", "uint32":
		g.recordUsedImport("hostarch")
		g.emit("*%s = %s(%s(hostarch.ByteOrder.Uint32(%s[:4])))\n", accessor, typeCast, typ, bufVar)
	case "int64", "uint64":
		g.recordUsedImport("hostarch")
		g.emit("*%s = %s(%s(hostarch.ByteOrder.Uint64(%s[:8])))\n", accessor, typeCast, typ, bufVar)
	default:
		g.emit("// Explicilty cast to the underlying type before dispatching to\n")
		g.emit("// UnmarshalBytes, so we don't recursively call %s.UnmarshalBytes\n", accessor)
		g.emit("inner := (*%s)(%s)\n", typ, accessor)
		g.emit("inner.UnmarshalBytes(%s[:%s.SizeBytes()])\n", bufVar, accessor)
	}
}

func (g *interfaceGenerator) validatePrimitiveNewtype(t *ast.Ident) {
	switch t.Name {
	case "int8", "uint8", "byte", "int16", "uint16", "int32", "uint32", "int64", "uint64":
		// These are the only primitive types we're allow. Below, we provide
		// suggestions for some disallowed types and reject them, then attempt
		// to marshal any remaining types by invoking the marshal.Marshallable
		// interface on them. If these types don't actually implement
		// marshal.Marshallable, compilation of the generated code will fail
		// with an appropriate error message.
		return
	case "int":
		g.abortAt(t.Pos(), "Type 'int' has ambiguous width, use int32 or int64")
	case "uint":
		g.abortAt(t.Pos(), "Type 'uint' has ambiguous width, use uint32 or uint64")
	case "string":
		g.abortAt(t.Pos(), "Type 'string' is dynamically-sized and cannot be marshalled, use a fixed size byte array '[...]byte' instead")
	default:
		debugfAt(g.f.Position(t.Pos()), fmt.Sprintf("Found derived type '%s', will attempt dispatch via marshal.Marshallable.\n", t.Name))
	}
}

// emitMarshallableForPrimitiveNewtype outputs code to implement the
// marshal.Marshallable interface for a newtype on a primitive. Primitive
// newtypes are always packed, so we can omit the various fallbacks required for
// non-packed structs.
func (g *interfaceGenerator) emitMarshallableForPrimitiveNewtype(nt *ast.Ident) {
	g.recordUsedImport("gohacks")
	g.recordUsedImport("hostarch")
	g.recordUsedImport("io")
	g.recordUsedImport("marshal")
	g.recordUsedImport("reflect")
	g.recordUsedImport("runtime")
	g.recordUsedImport("unsafe")

	g.emit("// SizeBytes implements marshal.Marshallable.SizeBytes.\n")
	g.emit("//go:nosplit\n")
	g.emit("func (%s *%s) SizeBytes() int {\n", g.r, g.typeName())
	g.inIndent(func() {
		if size, dynamic := g.scalarSize(nt); !dynamic {
			g.emit("return %d\n", size)
		} else {
			g.emit("return (*%s)(nil).SizeBytes()\n", nt.Name)
		}
	})
	g.emit("}\n\n")

	g.emit("// MarshalBytes implements marshal.Marshallable.MarshalBytes.\n")
	g.emit("func (%s *%s) MarshalBytes(dst []byte) []byte {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.marshalPrimitiveScalar(g.r, nt.Name, "dst")
		if size, dynamic := g.scalarSize(nt); !dynamic {
			g.emit("return dst[%d:]\n", size)
		} else {
			g.emit("return dst[(*%s)(nil).SizeBytes():]\n", nt.Name)
		}
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.\n")
	g.emit("func (%s *%s) UnmarshalBytes(src []byte) []byte {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.unmarshalPrimitiveScalar(g.r, nt.Name, "src", g.typeName())
		if size, dynamic := g.scalarSize(nt); !dynamic {
			g.emit("return src[%d:]\n", size)
		} else {
			g.emit("return src[(*%s)(nil).SizeBytes():]\n", nt.Name)
		}
	})
	g.emit("}\n\n")

	g.emit("// Packed implements marshal.Marshallable.Packed.\n")
	g.emit("//go:nosplit\n")
	g.emit("func (%s *%s) Packed() bool {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Scalar newtypes are always packed.\n")
		g.emit("return true\n")
	})
	g.emit("}\n\n")

	g.emit("// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.\n")
	g.emit("func (%s *%s) MarshalUnsafe(dst []byte) []byte {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("size := %s.SizeBytes()\n", g.r)
		g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(%s), uintptr(size))\n", g.r)
		g.emit("return dst[size:]\n")
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.\n")
	g.emit("func (%s *%s) UnmarshalUnsafe(src []byte) []byte {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("size := %s.SizeBytes()\n", g.r)
		g.emit("gohacks.Memmove(unsafe.Pointer(%s), unsafe.Pointer(&src[0]), uintptr(size))\n", g.r)
		g.emit("return src[size:]\n")
	})
	g.emit("}\n\n")

	g.emit("// CopyOutN implements marshal.Marshallable.CopyOutN.\n")
	g.emit("//go:nosplit\n")
	g.emit("func (%s *%s) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emitCastToByteSlice(g.r, "buf", fmt.Sprintf("%s.SizeBytes()", g.r))

		g.emit("length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.\n")
		g.emitKeepAlive(g.r)
		g.emit("return length, err\n")
	})
	g.emit("}\n\n")

	g.emit("// CopyOut implements marshal.Marshallable.CopyOut.\n")
	g.emit("//go:nosplit\n")
	g.emit("func (%s *%s) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("return %s.CopyOutN(cc, addr, %s.SizeBytes())\n", g.r, g.r)
	})
	g.emit("}\n\n")

	g.emit("// CopyIn implements marshal.Marshallable.CopyIn.\n")
	g.emit("//go:nosplit\n")
	g.emit("func (%s *%s) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emitCastToByteSlice(g.r, "buf", fmt.Sprintf("%s.SizeBytes()", g.r))

		g.emit("length, err := cc.CopyInBytes(addr, buf) // escapes: okay.\n")
		g.emitKeepAlive(g.r)
		g.emit("return length, err\n")
	})
	g.emit("}\n\n")

	g.emit("// WriteTo implements io.WriterTo.WriteTo.\n")
	g.emit("func (%s *%s) WriteTo(writer io.Writer) (int64, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emitCastToByteSlice(g.r, "buf", fmt.Sprintf("%s.SizeBytes()", g.r))

		g.emit("length, err := writer.Write(buf)\n")
		g.emitKeepAlive(g.r)
		g.emit("return int64(length), err\n")

	})
	g.emit("}\n\n")
}

func (g *interfaceGenerator) emitCheckedMarshallableForPrimitiveNewtype() {
	g.emit("// CheckedMarshal implements marshal.CheckedMarshallable.CheckedMarshal.\n")
	g.emit("func (%s *%s) CheckedMarshal(dst []byte) ([]byte, bool) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("size := %s.SizeBytes()\n", g.r)
		g.emit("if size > len(dst) {\n")
		g.inIndent(func() {
			g.emit("return dst, false\n")
		})
		g.emit("}\n")
		g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(%s), uintptr(size))\n", g.r)
		g.emit("return dst[size:], true\n")
	})
	g.emit("}\n\n")

	g.emit("// CheckedUnmarshal implements marshal.CheckedMarshallable.CheckedUnmarshal.\n")
	g.emit("func (%s *%s) CheckedUnmarshal(src []byte) ([]byte, bool) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("size := %s.SizeBytes()\n", g.r)
		g.emit("if size > len(src) {\n")
		g.inIndent(func() {
			g.emit("return src, false\n")
		})
		g.emit("}\n")
		g.emit("gohacks.Memmove(unsafe.Pointer(%s), unsafe.Pointer(&src[0]), uintptr(size))\n", g.r)
		g.emit("return src[size:], true\n")
	})
	g.emit("}\n\n")
}

func (g *interfaceGenerator) emitMarshallableSliceForPrimitiveNewtype(nt *ast.Ident, slice *sliceAPI) {
	g.recordUsedImport("marshal")
	g.recordUsedImport("hostarch")
	g.recordUsedImport("reflect")
	g.recordUsedImport("runtime")
	g.recordUsedImport("unsafe")

	eltType := g.typeName()
	if slice.inner {
		eltType = nt.Name
	}

	g.emit("// Copy%sIn copies in a slice of %s objects from the task's memory.\n", slice.ident, eltType)
	g.emit("//go:nosplit\n")
	g.emit("func Copy%sIn(cc marshal.CopyContext, addr hostarch.Addr, dst []%s) (int, error) {\n", slice.ident, eltType)
	g.inIndent(func() {
		g.emit("count := len(dst)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return 0, nil\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		g.emitCastSliceToByteSlice("&dst", "buf", "size * count")

		g.emit("length, err := cc.CopyInBytes(addr, buf) // escapes: okay.\n")
		g.emitKeepAlive("dst")
		g.emit("return length, err\n")
	})
	g.emit("}\n\n")

	g.emit("// Copy%sOut copies a slice of %s objects to the task's memory.\n", slice.ident, eltType)
	g.emit("//go:nosplit\n")
	g.emit("func Copy%sOut(cc marshal.CopyContext, addr hostarch.Addr, src []%s) (int, error) {\n", slice.ident, eltType)
	g.inIndent(func() {
		g.emit("count := len(src)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return 0, nil\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		g.emitCastSliceToByteSlice("&src", "buf", "size * count")

		g.emit("length, err := cc.CopyOutBytes(addr, buf) // escapes: okay.\n")
		g.emitKeepAlive("src")
		g.emit("return length, err\n")
	})
	g.emit("}\n\n")

	g.emit("// MarshalUnsafe%s is like %s.MarshalUnsafe, but for a []%s.\n", slice.ident, g.typeName(), g.typeName())
	g.emit("func MarshalUnsafe%s(src []%s, dst []byte) []byte {\n", slice.ident, g.typeName())
	g.inIndent(func() {
		g.emit("count := len(src)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return dst\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		g.emit("buf := dst[:size*count]\n")
		g.emit("gohacks.Memmove(unsafe.Pointer(&buf[0]), unsafe.Pointer(&src[0]), uintptr(len(buf)))\n")
		g.emit("return dst[size*count:]\n")
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe%s is like %s.UnmarshalUnsafe, but for a []%s.\n", slice.ident, g.typeName(), g.typeName())
	g.emit("func UnmarshalUnsafe%s(dst []%s, src []byte) []byte {\n", slice.ident, g.typeName())
	g.inIndent(func() {
		g.emit("count := len(dst)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return src\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		g.emit("buf := src[:size*count]\n")
		g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&buf[0]), uintptr(len(buf)))\n")
		g.emit("return src[size*count:]\n")
	})
	g.emit("}\n\n")
}
