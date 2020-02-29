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
// newtypes on arrays.

package gomarshal

import (
	"fmt"
	"go/ast"
)

func (g *interfaceGenerator) validateArrayNewtype(n *ast.Ident, a *ast.ArrayType) {
	if a.Len == nil {
		g.abortAt(a.Pos(), fmt.Sprintf("Dynamically sized slice '%s' cannot be marshalled, arrays must be statically sized", n.Name))
	}

	if _, ok := a.Len.(*ast.BasicLit); !ok {
		g.abortAt(a.Len.Pos(), fmt.Sprintf("Array size must be a literal, don't use consts or expressions"))
	}

	if _, ok := a.Elt.(*ast.Ident); !ok {
		g.abortAt(a.Elt.Pos(), fmt.Sprintf("Marshalling not supported for arrays with %s elements, array elements must be primitive types", kindString(a.Elt)))
	}

	if arrayLen(a) <= 0 {
		g.abortAt(a.Len.Pos(), fmt.Sprintf("Marshalling not supported for zero length arrays, why does an ABI struct have one?"))
	}
}

func (g *interfaceGenerator) emitMarshallableForArrayNewtype(n, elt *ast.Ident, len int) {
	g.recordUsedImport("io")
	g.recordUsedImport("marshal")
	g.recordUsedImport("reflect")
	g.recordUsedImport("runtime")
	g.recordUsedImport("safecopy")
	g.recordUsedImport("unsafe")
	g.recordUsedImport("usermem")

	g.emit("// SizeBytes implements marshal.Marshallable.SizeBytes.\n")
	g.emit("func (%s *%s) SizeBytes() int {\n", g.r, g.typeName())
	g.inIndent(func() {
		if size, dynamic := g.scalarSize(elt); !dynamic {
			g.emit("return %d\n", size*len)
		} else {
			g.emit("return (*%s)(nil).SizeBytes() * %d\n", n.Name, len)
		}
	})
	g.emit("}\n\n")

	g.emit("// MarshalBytes implements marshal.Marshallable.MarshalBytes.\n")
	g.emit("func (%s *%s) MarshalBytes(dst []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("for idx := 0; idx < %d; idx++ {\n", len)
		g.inIndent(func() {
			g.marshalScalar(fmt.Sprintf("%s[idx]", g.r), elt.Name, "dst")
		})
		g.emit("}\n")
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.\n")
	g.emit("func (%s *%s) UnmarshalBytes(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("for idx := 0; idx < %d; idx++ {\n", len)
		g.inIndent(func() {
			g.unmarshalScalar(fmt.Sprintf("%s[idx]", g.r), elt.Name, "src")
		})
		g.emit("}\n")
	})
	g.emit("}\n\n")

	g.emit("// Packed implements marshal.Marshallable.Packed.\n")
	g.emit("func (%s *%s) Packed() bool {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Array newtypes are always packed.\n")
		g.emit("return true\n")
	})
	g.emit("}\n\n")

	g.emit("// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.\n")
	g.emit("func (%s *%s) MarshalUnsafe(dst []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("safecopy.CopyIn(dst, unsafe.Pointer(%s))\n", g.r)
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.\n")
	g.emit("func (%s *%s) UnmarshalUnsafe(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("safecopy.CopyOut(unsafe.Pointer(%s), src)\n", g.r)
	})
	g.emit("}\n\n")

	g.emit("// CopyOut implements marshal.Marshallable.CopyOut.\n")
	g.emit("func (%s *%s) CopyOut(task marshal.Task, addr usermem.Addr) error {\n", g.r, g.typeName())
	g.inIndent(func() {
		// Fast serialization.
		g.emit("// Bypass escape analysis on %s. The no-op arithmetic operation on the\n", g.r)
		g.emit("// pointer makes the compiler think val doesn't depend on %s.\n", g.r)
		g.emit("// See src/runtime/stubs.go:noescape() in the golang toolchain.\n")
		g.emit("ptr := unsafe.Pointer(%s)\n", g.r)
		g.emit("val := uintptr(ptr)\n")
		g.emit("val = val^0\n\n")

		g.emit("// Construct a slice backed by %s's underlying memory.\n", g.r)
		g.emit("var buf []byte\n")
		g.emit("hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))\n")
		g.emit("hdr.Data = val\n")
		g.emit("hdr.Len = %s.SizeBytes()\n", g.r)
		g.emit("hdr.Cap = %s.SizeBytes()\n\n", g.r)

		g.emit("_, err := task.CopyOutBytes(addr, buf)\n")
		g.emit("// Since we bypassed the compiler's escape analysis, indicate that %s\n", g.r)
		g.emit("// must live until after the CopyOutBytes.\n")
		g.emit("runtime.KeepAlive(%s)\n", g.r)
		g.emit("return err\n")
	})
	g.emit("}\n\n")

	g.emit("// CopyIn implements marshal.Marshallable.CopyIn.\n")
	g.emit("func (%s *%s) CopyIn(task marshal.Task, addr usermem.Addr) error {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Bypass escape analysis on %s. The no-op arithmetic operation on the\n", g.r)
		g.emit("// pointer makes the compiler think val doesn't depend on %s.\n", g.r)
		g.emit("// See src/runtime/stubs.go:noescape() in the golang toolchain.\n")
		g.emit("ptr := unsafe.Pointer(%s)\n", g.r)
		g.emit("val := uintptr(ptr)\n")
		g.emit("val = val^0\n\n")

		g.emit("// Construct a slice backed by %s's underlying memory.\n", g.r)
		g.emit("var buf []byte\n")
		g.emit("hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))\n")
		g.emit("hdr.Data = val\n")
		g.emit("hdr.Len = %s.SizeBytes()\n", g.r)
		g.emit("hdr.Cap = %s.SizeBytes()\n\n", g.r)

		g.emit("_, err := task.CopyInBytes(addr, buf)\n")
		g.emit("// Since we bypassed the compiler's escape analysis, indicate that %s\n", g.r)
		g.emit("// must live until after the CopyInBytes.\n")
		g.emit("runtime.KeepAlive(%s)\n", g.r)
		g.emit("return err\n")
	})
	g.emit("}\n\n")

	g.emit("// WriteTo implements io.WriterTo.WriteTo.\n")
	g.emit("func (%s *%s) WriteTo(w io.Writer) (int64, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Bypass escape analysis on %s. The no-op arithmetic operation on the\n", g.r)
		g.emit("// pointer makes the compiler think val doesn't depend on %s.\n", g.r)
		g.emit("// See src/runtime/stubs.go:noescape() in the golang toolchain.\n")
		g.emit("ptr := unsafe.Pointer(%s)\n", g.r)
		g.emit("val := uintptr(ptr)\n")
		g.emit("val = val^0\n\n")

		g.emit("// Construct a slice backed by %s's underlying memory.\n", g.r)
		g.emit("var buf []byte\n")
		g.emit("hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))\n")
		g.emit("hdr.Data = val\n")
		g.emit("hdr.Len = %s.SizeBytes()\n", g.r)
		g.emit("hdr.Cap = %s.SizeBytes()\n\n", g.r)

		g.emit("len, err := w.Write(buf)\n")
		g.emit("// Since we bypassed the compiler's escape analysis, indicate that %s\n", g.r)
		g.emit("// must live until after the Write.\n")
		g.emit("runtime.KeepAlive(%s)\n", g.r)
		g.emit("return int64(len), err\n")

	})
	g.emit("}\n\n")
}
