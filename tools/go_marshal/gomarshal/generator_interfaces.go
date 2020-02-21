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

	// as records embedded fields in t that are potentially not packed. The key
	// is the accessor for the field.
	as map[string]struct{}
}

// typeName returns the name of the type this g represents.
func (g *interfaceGenerator) typeName() string {
	return g.t.Name.Name
}

// newinterfaceGenerator creates a new interface generator.
func newInterfaceGenerator(t *ast.TypeSpec, fset *token.FileSet) *interfaceGenerator {
	g := &interfaceGenerator{
		t:  t,
		r:  receiverName(t),
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

func (g *interfaceGenerator) forEachField(fn func(f *ast.Field)) {
	// This is guaranteed to succeed because g.t is always a struct.
	st := g.t.Type.(*ast.StructType)
	for _, field := range st.Fields.List {
		fn(field)
	}
}

func (g *interfaceGenerator) fieldAccessor(n *ast.Ident) string {
	return fmt.Sprintf("%s.%s", g.r, n.Name)
}

// abortAt aborts the go_marshal tool with the given error message, with a
// reference position to the input source. Same as abortAt, but uses g to
// resolve p to position.
func (g *interfaceGenerator) abortAt(p token.Pos, msg string) {
	abortAt(g.f.Position(p), msg)
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

// validateStruct ensures the type we're working with can be marshalled. These
// checks are done ahead of time and in one place so we can make assumptions
// later.
func (g *interfaceGenerator) validateStruct() {
	g.forEachField(func(f *ast.Field) {
		if len(f.Names) == 0 {
			g.abortAt(f.Pos(), "Cannot marshal structs with embedded fields, give the field a name; use '_' for anonymous fields such as padding fields")
		}
	})

	g.forEachField(func(f *ast.Field) {
		fieldDispatcher{
			primitive: func(_, t *ast.Ident) {
				g.validatePrimitiveNewtype(t)
			},
			selector: func(_, _, _ *ast.Ident) {
				// No validation to perform on selector fields. However this
				// callback must still be provided.
			},
			array: func(n, _ *ast.Ident, len int) {
				a := f.Type.(*ast.ArrayType)
				if a.Len == nil {
					g.abortAt(f.Pos(), fmt.Sprintf("Dynamically sized slice '%s' cannot be marshalled, arrays must be statically sized", n.Name))
				}

				if _, ok := a.Len.(*ast.BasicLit); !ok {
					g.abortAt(a.Len.Pos(), fmt.Sprintf("Array size must be a literal, don's use consts or expressions"))
				}

				if _, ok := a.Elt.(*ast.Ident); !ok {
					g.abortAt(a.Elt.Pos(), fmt.Sprintf("Marshalling not supported for arrays with %s elements, array elements must be primitive types", kindString(a.Elt)))
				}

				if len <= 0 {
					g.abortAt(a.Len.Pos(), fmt.Sprintf("Marshalling not supported for zero length arrays, why does an ABI struct have one?"))
				}
			},
			unhandled: func(_ *ast.Ident) {
				g.abortAt(f.Pos(), fmt.Sprintf("Marshalling not supported for %s fields", kindString(f.Type)))
			},
		}.dispatch(f)
	})
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

// marshalStructFieldScalar writes a single scalar field from a struct to a byte slice.
func (g *interfaceGenerator) marshalStructFieldScalar(accessor, typ, bufVar string) {
	switch typ {
	case "int8", "uint8", "byte":
		g.emit("%s[0] = byte(%s)\n", bufVar, accessor)
		g.shift(bufVar, 1)
	case "int16", "uint16":
		g.recordUsedImport("usermem")
		g.emit("usermem.ByteOrder.PutUint16(%s[:2], uint16(%s))\n", bufVar, accessor)
		g.shift(bufVar, 2)
	case "int32", "uint32":
		g.recordUsedImport("usermem")
		g.emit("usermem.ByteOrder.PutUint32(%s[:4], uint32(%s))\n", bufVar, accessor)
		g.shift(bufVar, 4)
	case "int64", "uint64":
		g.recordUsedImport("usermem")
		g.emit("usermem.ByteOrder.PutUint64(%s[:8], uint64(%s))\n", bufVar, accessor)
		g.shift(bufVar, 8)
	default:
		g.emit("%s.MarshalBytes(%s[:%s.SizeBytes()])\n", accessor, bufVar, accessor)
		g.shiftDynamic(bufVar, accessor)
	}
}

// unmarshalStructFieldScalar reads a single scalar field from a struct, from a
// byte slice.
func (g *interfaceGenerator) unmarshalStructFieldScalar(accessor, typ, bufVar string) {
	switch typ {
	case "byte":
		g.emit("%s = %s[0]\n", accessor, bufVar)
		g.shift(bufVar, 1)
	case "int8", "uint8":
		g.emit("%s = %s(%s[0])\n", accessor, typ, bufVar)
		g.shift(bufVar, 1)
	case "int16", "uint16":
		g.recordUsedImport("usermem")
		g.emit("%s = %s(usermem.ByteOrder.Uint16(%s[:2]))\n", accessor, typ, bufVar)
		g.shift(bufVar, 2)
	case "int32", "uint32":
		g.recordUsedImport("usermem")
		g.emit("%s = %s(usermem.ByteOrder.Uint32(%s[:4]))\n", accessor, typ, bufVar)
		g.shift(bufVar, 4)
	case "int64", "uint64":
		g.recordUsedImport("usermem")
		g.emit("%s = %s(usermem.ByteOrder.Uint64(%s[:8]))\n", accessor, typ, bufVar)
		g.shift(bufVar, 8)
	default:
		g.emit("%s.UnmarshalBytes(%s[:%s.SizeBytes()])\n", accessor, bufVar, accessor)
		g.shiftDynamic(bufVar, accessor)
		g.recordPotentiallyNonPackedField(accessor)
	}
}

// marshalPrimitiveScalar writes a single primitive variable to a byte slice.
func (g *interfaceGenerator) marshalPrimitiveScalar(accessor, typ, bufVar string) {
	switch typ {
	case "int8", "uint8", "byte":
		g.emit("%s[0] = byte(*%s)\n", bufVar, accessor)
	case "int16", "uint16":
		g.recordUsedImport("usermem")
		g.emit("usermem.ByteOrder.PutUint16(%s[:2], uint16(*%s))\n", bufVar, accessor)
	case "int32", "uint32":
		g.recordUsedImport("usermem")
		g.emit("usermem.ByteOrder.PutUint32(%s[:4], uint32(*%s))\n", bufVar, accessor)
	case "int64", "uint64":
		g.recordUsedImport("usermem")
		g.emit("usermem.ByteOrder.PutUint64(%s[:8], uint64(*%s))\n", bufVar, accessor)
	default:
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
		g.recordUsedImport("usermem")
		g.emit("*%s = %s(%s(usermem.ByteOrder.Uint16(%s[:2])))\n", accessor, typeCast, typ, bufVar)
	case "int32", "uint32":
		g.recordUsedImport("usermem")
		g.emit("*%s = %s(%s(usermem.ByteOrder.Uint32(%s[:4])))\n", accessor, typeCast, typ, bufVar)

	case "int64", "uint64":
		g.recordUsedImport("usermem")
		g.emit("*%s = %s(%s(usermem.ByteOrder.Uint64(%s[:8])))\n", accessor, typeCast, typ, bufVar)
	default:
		g.emit("inner := (*%s)(%s)\n", typ, accessor)
		g.emit("inner.UnmarshalBytes(%s[:%s.SizeBytes()])\n", bufVar, accessor)
	}
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

func (g *interfaceGenerator) emitMarshallableForStruct() {
	// Is g.t a packed struct without consideing field types?
	thisPacked := true
	g.forEachField(func(f *ast.Field) {
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

		g.forEachField(fieldDispatcher{
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
		g.forEachField(fieldDispatcher{
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
				g.marshalStructFieldScalar(g.fieldAccessor(n), t.Name, "dst")
			},
			selector: func(n, tX, tSel *ast.Ident) {
				g.marshalStructFieldScalar(g.fieldAccessor(n), fmt.Sprintf("%s.%s", tX.Name, tSel.Name), "dst")
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
					g.marshalStructFieldScalar(fmt.Sprintf("%s[idx]", g.fieldAccessor(n)), t.Name, "dst")
				})
				g.emit("}\n")
			},
		}.dispatch)
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.\n")
	g.emit("func (%s *%s) UnmarshalBytes(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.forEachField(fieldDispatcher{
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
				g.unmarshalStructFieldScalar(g.fieldAccessor(n), t.Name, "src")
			},
			selector: func(n, tX, tSel *ast.Ident) {
				g.unmarshalStructFieldScalar(g.fieldAccessor(n), fmt.Sprintf("%s.%s", tX.Name, tSel.Name), "src")
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
					g.unmarshalStructFieldScalar(fmt.Sprintf("%s[idx]", g.fieldAccessor(n)), t.Name, "src")
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

// emitMarshallableForPrimitiveNewtype outputs code to implement the
// marshal.Marshallable interface for a newtype on a primitive. Primitive
// newtypes are always packed, so we can omit the various fallbacks required for
// non-packed structs.
func (g *interfaceGenerator) emitMarshallableForPrimitiveNewtype() {
	g.recordUsedImport("io")
	g.recordUsedImport("marshal")
	g.recordUsedImport("reflect")
	g.recordUsedImport("runtime")
	g.recordUsedImport("safecopy")
	g.recordUsedImport("unsafe")
	g.recordUsedImport("usermem")

	nt := g.t.Type.(*ast.Ident)

	g.emit("// SizeBytes implements marshal.Marshallable.SizeBytes.\n")
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
	g.emit("func (%s *%s) MarshalBytes(dst []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.marshalPrimitiveScalar(g.r, nt.Name, "dst")
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.\n")
	g.emit("func (%s *%s) UnmarshalBytes(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.unmarshalPrimitiveScalar(g.r, nt.Name, "src", g.typeName())
	})
	g.emit("}\n\n")

	g.emit("// Packed implements marshal.Marshallable.Packed.\n")
	g.emit("func (%s *%s) Packed() bool {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Scalar newtypes are always packed.\n")
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
