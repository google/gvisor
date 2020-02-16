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
// structs.

package gomarshal

import (
	"fmt"
	"go/ast"
	"strings"
)

func (g *interfaceGenerator) fieldAccessor(n *ast.Ident) string {
	return fmt.Sprintf("%s.%s", g.r, n.Name)
}

// areFieldsPackedExpression returns a go expression checking whether g.t's fields are
// packed. Returns "", false if g.t has no fields that may be potentially
// packed, otherwise returns <clause>, true, where <clause> is an expression
// like "t.a.Packed() && t.b.Packed() && t.c.Packed()".
func (g *interfaceGenerator) areFieldsPackedExpression() (string, bool) {
	if len(g.as) == 0 {
		return "", false
	}

	cs := make([]string, 0, len(g.as))
	for accessor, _ := range g.as {
		cs = append(cs, fmt.Sprintf("%s.Packed()", accessor))
	}
	return strings.Join(cs, " && "), true
}

// validateStruct ensures the type we're working with can be marshalled. These
// checks are done ahead of time and in one place so we can make assumptions
// later.
func (g *interfaceGenerator) validateStruct(ts *ast.TypeSpec, st *ast.StructType) {
	forEachStructField(st, func(f *ast.Field) {
		if len(f.Names) == 0 {
			g.abortAt(f.Pos(), "Cannot marshal structs with embedded fields, give the field a name; use '_' for anonymous fields such as padding fields")
		}
	})

	forEachStructField(st, func(f *ast.Field) {
		fieldDispatcher{
			primitive: func(_, t *ast.Ident) {
				g.validatePrimitiveNewtype(t)
			},
			selector: func(_, _, _ *ast.Ident) {
				// No validation to perform on selector fields. However this
				// callback must still be provided.
			},
			array: func(n, _ *ast.Ident, len int) {
				g.validateArrayNewtype(n, f.Type.(*ast.ArrayType))
			},
			unhandled: func(_ *ast.Ident) {
				g.abortAt(f.Pos(), fmt.Sprintf("Marshalling not supported for %s fields", kindString(f.Type)))
			},
		}.dispatch(f)
	})
}

func (g *interfaceGenerator) emitMarshallableForStruct(st *ast.StructType) {
	// Is g.t a packed struct without consideing field types?
	thisPacked := true
	forEachStructField(st, func(f *ast.Field) {
		if f.Tag != nil {
			if f.Tag.Value == "`marshal:\"unaligned\"`" {
				if thisPacked {
					debugfAt(g.f.Position(g.t.Pos()),
						fmt.Sprintf("Marking type '%s' as not packed due to tag `marshal:\"unaligned\"`.\n", g.t.Name))
					thisPacked = false
				}
			}
		}
	})

	g.emit("// SizeBytes implements marshal.Marshallable.SizeBytes.\n")
	g.emit("func (%s *%s) SizeBytes() int {\n", g.r, g.typeName())
	g.inIndent(func() {
		primitiveSize := 0
		var dynamicSizeTerms []string

		forEachStructField(st, fieldDispatcher{
			primitive: func(n, t *ast.Ident) {
				if size, dynamic := g.scalarSize(t); !dynamic {
					primitiveSize += size
				} else {
					g.recordUsedMarshallable(t.Name)
					dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("(*%s)(nil).SizeBytes()", t.Name))
				}
			},
			selector: func(n, tX, tSel *ast.Ident) {
				tName := fmt.Sprintf("%s.%s", tX.Name, tSel.Name)
				g.recordUsedImport(tX.Name)
				g.recordUsedMarshallable(tName)
				dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("(*%s)(nil).SizeBytes()", tName))
			},
			array: func(n, t *ast.Ident, len int) {
				if len < 1 {
					// Zero-length arrays should've been rejected by validate().
					panic("unreachable")
				}
				if size, dynamic := g.scalarSize(t); !dynamic {
					primitiveSize += size * len
				} else {
					g.recordUsedMarshallable(t.Name)
					dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("(*%s)(nil).SizeBytes()*%d", t.Name, len))
				}
			},
		}.dispatch)
		g.emit("return %d", primitiveSize)
		if len(dynamicSizeTerms) > 0 {
			g.incIndent()
		}
		{
			for _, d := range dynamicSizeTerms {
				g.emitNoIndent(" +\n")
				g.emit(d)
			}
		}
		if len(dynamicSizeTerms) > 0 {
			g.decIndent()
		}
	})
	g.emit("\n}\n\n")

	g.emit("// MarshalBytes implements marshal.Marshallable.MarshalBytes.\n")
	g.emit("func (%s *%s) MarshalBytes(dst []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		forEachStructField(st, fieldDispatcher{
			primitive: func(n, t *ast.Ident) {
				if n.Name == "_" {
					g.emit("// Padding: dst[:sizeof(%s)] ~= %s(0)\n", t.Name, t.Name)
					if len, dynamic := g.scalarSize(t); !dynamic {
						g.shift("dst", len)
					} else {
						// We can't use shiftDynamic here because we don't have
						// an instance of the dynamic type we can referece here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("dst = dst[(*%s)(nil).SizeBytes():]\n", t.Name)
					}
					return
				}
				g.marshalScalar(g.fieldAccessor(n), t.Name, "dst")
			},
			selector: func(n, tX, tSel *ast.Ident) {
				g.marshalScalar(g.fieldAccessor(n), fmt.Sprintf("%s.%s", tX.Name, tSel.Name), "dst")
			},
			array: func(n, t *ast.Ident, size int) {
				if n.Name == "_" {
					g.emit("// Padding: dst[:sizeof(%s)*%d] ~= [%d]%s{0}\n", t.Name, size, size, t.Name)
					if len, dynamic := g.scalarSize(t); !dynamic {
						g.shift("dst", len*size)
					} else {
						// We can't use shiftDynamic here because we don't have
						// an instance of the dynamic type we can reference here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("dst = dst[(*%s)(nil).SizeBytes()*%d:]\n", t.Name, size)
					}
					return
				}

				g.emit("for idx := 0; idx < %d; idx++ {\n", size)
				g.inIndent(func() {
					g.marshalScalar(fmt.Sprintf("%s[idx]", g.fieldAccessor(n)), t.Name, "dst")
				})
				g.emit("}\n")
			},
		}.dispatch)
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.\n")
	g.emit("func (%s *%s) UnmarshalBytes(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		forEachStructField(st, fieldDispatcher{
			primitive: func(n, t *ast.Ident) {
				if n.Name == "_" {
					g.emit("// Padding: var _ %s ~= src[:sizeof(%s)]\n", t.Name, t.Name)
					if len, dynamic := g.scalarSize(t); !dynamic {
						g.shift("src", len)
					} else {
						// We can't use shiftDynamic here because we don't have
						// an instance of the dynamic type we can reference here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("src = src[(*%s)(nil).SizeBytes():]\n", t.Name)
						g.recordPotentiallyNonPackedField(fmt.Sprintf("(*%s)(nil)", t.Name))
					}
					return
				}
				g.unmarshalScalar(g.fieldAccessor(n), t.Name, "src")
			},
			selector: func(n, tX, tSel *ast.Ident) {
				g.unmarshalScalar(g.fieldAccessor(n), fmt.Sprintf("%s.%s", tX.Name, tSel.Name), "src")
			},
			array: func(n, t *ast.Ident, size int) {
				if n.Name == "_" {
					g.emit("// Padding: ~ copy([%d]%s(%s), src[:sizeof(%s)*%d])\n", size, t.Name, g.fieldAccessor(n), t.Name, size)
					if len, dynamic := g.scalarSize(t); !dynamic {
						g.shift("src", len*size)
					} else {
						// We can't use shiftDynamic here because we don't have
						// an instance of the dynamic type we can referece here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("src = src[(*%s)(nil).SizeBytes()*%d:]\n", t.Name, size)
					}
					return
				}

				g.emit("for idx := 0; idx < %d; idx++ {\n", size)
				g.inIndent(func() {
					g.unmarshalScalar(fmt.Sprintf("%s[idx]", g.fieldAccessor(n)), t.Name, "src")
				})
				g.emit("}\n")
			},
		}.dispatch)
	})
	g.emit("}\n\n")

	g.emit("// Packed implements marshal.Marshallable.Packed.\n")
	g.emit("func (%s *%s) Packed() bool {\n", g.r, g.typeName())
	g.inIndent(func() {
		expr, fieldsMaybePacked := g.areFieldsPackedExpression()
		switch {
		case !thisPacked:
			g.emit("return false\n")
		case fieldsMaybePacked:
			g.emit("return %s\n", expr)
		default:
			g.emit("return true\n")

		}
	})
	g.emit("}\n\n")

	g.emit("// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.\n")
	g.emit("func (%s *%s) MarshalUnsafe(dst []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		if thisPacked {
			g.recordUsedImport("safecopy")
			g.recordUsedImport("unsafe")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if %s {\n", cond)
				g.inIndent(func() {
					g.emit("safecopy.CopyIn(dst, unsafe.Pointer(%s))\n", g.r)
				})
				g.emit("} else {\n")
				g.inIndent(func() {
					g.emit("%s.MarshalBytes(dst)\n", g.r)
				})
				g.emit("}\n")
			} else {
				g.emit("safecopy.CopyIn(dst, unsafe.Pointer(%s))\n", g.r)
			}
		} else {
			g.emit("// Type %s doesn't have a packed layout in memory, fallback to MarshalBytes.\n", g.typeName())
			g.emit("%s.MarshalBytes(dst)\n", g.r)
		}
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.\n")
	g.emit("func (%s *%s) UnmarshalUnsafe(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		if thisPacked {
			g.recordUsedImport("safecopy")
			g.recordUsedImport("unsafe")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if %s {\n", cond)
				g.inIndent(func() {
					g.emit("safecopy.CopyOut(unsafe.Pointer(%s), src)\n", g.r)
				})
				g.emit("} else {\n")
				g.inIndent(func() {
					g.emit("%s.UnmarshalBytes(src)\n", g.r)
				})
				g.emit("}\n")
			} else {
				g.emit("safecopy.CopyOut(unsafe.Pointer(%s), src)\n", g.r)
			}
		} else {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to UnmarshalBytes.\n", g.typeName())
			g.emit("%s.UnmarshalBytes(src)\n", g.r)
		}
	})
	g.emit("}\n\n")

	g.emit("// CopyOut implements marshal.Marshallable.CopyOut.\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("usermem")
	g.emit("func (%s *%s) CopyOut(task marshal.Task, addr usermem.Addr) error {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
			g.emit("buf := task.CopyScratchBuffer(%s.SizeBytes())\n", g.r)
			g.emit("%s.MarshalBytes(buf)\n", g.r)
			g.emit("_, err := task.CopyOutBytes(addr, buf)\n")
			g.emit("return err\n")
		}
		if thisPacked {
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			g.recordUsedImport("unsafe")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !%s {\n", cond)
				g.inIndent(fallback)
				g.emit("}\n\n")
			}
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
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// CopyIn implements marshal.Marshallable.CopyIn.\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("usermem")
	g.emit("func (%s *%s) CopyIn(task marshal.Task, addr usermem.Addr) error {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to UnmarshalBytes.\n", g.typeName())
			g.emit("buf := task.CopyScratchBuffer(%s.SizeBytes())\n", g.r)
			g.emit("_, err := task.CopyInBytes(addr, buf)\n")
			g.emit("if err != nil {\n")
			g.inIndent(func() {
				g.emit("return err\n")
			})
			g.emit("}\n")

			g.emit("%s.UnmarshalBytes(buf)\n", g.r)
			g.emit("return nil\n")
		}
		if thisPacked {
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			g.recordUsedImport("unsafe")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !%s {\n", cond)
				g.inIndent(fallback)
				g.emit("}\n\n")
			}
			// Fast deserialization.
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
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// WriteTo implements io.WriterTo.WriteTo.\n")
	g.recordUsedImport("io")
	g.emit("func (%s *%s) WriteTo(w io.Writer) (int64, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
			g.emit("buf := make([]byte, %s.SizeBytes())\n", g.r)
			g.emit("%s.MarshalBytes(buf)\n", g.r)
			g.emit("n, err := w.Write(buf)\n")
			g.emit("return int64(n), err\n")
		}
		if thisPacked {
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			g.recordUsedImport("unsafe")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !%s {\n", cond)
				g.inIndent(fallback)
				g.emit("}\n\n")
			}
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

			g.emit("len, err := w.Write(buf)\n")
			g.emit("// Since we bypassed the compiler's escape analysis, indicate that %s\n", g.r)
			g.emit("// must live until after the Write.\n")
			g.emit("runtime.KeepAlive(%s)\n", g.r)
			g.emit("return int64(len), err\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")
}
