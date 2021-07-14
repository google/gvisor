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
	"sort"
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
	for accessor := range g.as {
		cs = append(cs, fmt.Sprintf("%s.Packed()", accessor))
	}
	// Sort expressions for determinstic build outputs.
	sort.Strings(cs)
	return strings.Join(cs, " && "), true
}

// validateStruct ensures the type we're working with can be marshalled. These
// checks are done ahead of time and in one place so we can make assumptions
// later.
func (g *interfaceGenerator) validateStruct(ts *ast.TypeSpec, st *ast.StructType) {
	forEachStructField(st, func(f *ast.Field) {
		fieldDispatcher{
			primitive: func(_, t *ast.Ident) {
				g.validatePrimitiveNewtype(t)
			},
			selector: func(_, _, _ *ast.Ident) {
				// No validation to perform on selector fields. However this
				// callback must still be provided.
			},
			array: func(n *ast.Ident, a *ast.ArrayType, _ *ast.Ident) {
				g.validateArrayNewtype(n, a)
			},
			unhandled: func(_ *ast.Ident) {
				g.abortAt(f.Pos(), fmt.Sprintf("Marshalling not supported for %s fields", kindString(f.Type)))
			},
		}.dispatch(f)
	})
}

func (g *interfaceGenerator) isStructPacked(st *ast.StructType) bool {
	packed := true
	forEachStructField(st, func(f *ast.Field) {
		if f.Tag != nil {
			if f.Tag.Value == "`marshal:\"unaligned\"`" {
				if packed {
					debugfAt(g.f.Position(g.t.Pos()),
						fmt.Sprintf("Marking type '%s' as not packed due to tag `marshal:\"unaligned\"`.\n", g.t.Name))
					packed = false
				}
			}
		}
	})
	return packed
}

func (g *interfaceGenerator) emitMarshallableForStruct(st *ast.StructType) {
	thisPacked := g.isStructPacked(st)

	g.emit("// SizeBytes implements marshal.Marshallable.SizeBytes.\n")
	g.emit("func (%s *%s) SizeBytes() int {\n", g.r, g.typeName())
	g.inIndent(func() {
		primitiveSize := 0
		var dynamicSizeTerms []string

		forEachStructField(st, fieldDispatcher{
			primitive: func(_, t *ast.Ident) {
				if size, dynamic := g.scalarSize(t); !dynamic {
					primitiveSize += size
				} else {
					g.recordUsedMarshallable(t.Name)
					dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("(*%s)(nil).SizeBytes()", t.Name))
				}
			},
			selector: func(_, tX, tSel *ast.Ident) {
				tName := fmt.Sprintf("%s.%s", tX.Name, tSel.Name)
				g.recordUsedImport(tX.Name)
				g.recordUsedMarshallable(tName)
				dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("(*%s)(nil).SizeBytes()", tName))
			},
			array: func(_ *ast.Ident, a *ast.ArrayType, t *ast.Ident) {
				lenExpr := g.arrayLenExpr(a)
				if size, dynamic := g.scalarSize(t); !dynamic {
					dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("%d*%s", size, lenExpr))
				} else {
					g.recordUsedMarshallable(t.Name)
					dynamicSizeTerms = append(dynamicSizeTerms, fmt.Sprintf("(*%s)(nil).SizeBytes()*%s", t.Name, lenExpr))
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
						// an instance of the dynamic type we can reference here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("dst = dst[(*%s)(nil).SizeBytes():]\n", t.Name)
					}
					return
				}
				g.marshalScalar(g.fieldAccessor(n), t.Name, "dst")
			},
			selector: func(n, tX, tSel *ast.Ident) {
				if n.Name == "_" {
					g.emit("// Padding: dst[:sizeof(%s)] ~= %s(0)\n", tX.Name, tSel.Name)
					g.emit("dst = dst[(*%s.%s)(nil).SizeBytes():]\n", tX.Name, tSel.Name)
					return
				}
				g.marshalScalar(g.fieldAccessor(n), fmt.Sprintf("%s.%s", tX.Name, tSel.Name), "dst")
			},
			array: func(n *ast.Ident, a *ast.ArrayType, t *ast.Ident) {
				lenExpr := g.arrayLenExpr(a)
				if n.Name == "_" {
					g.emit("// Padding: dst[:sizeof(%s)*%s] ~= [%s]%s{0}\n", t.Name, lenExpr, lenExpr, t.Name)
					if size, dynamic := g.scalarSize(t); !dynamic {
						g.emit("dst = dst[%d*(%s):]\n", size, lenExpr)
					} else {
						// We can't use shiftDynamic here because we don't have
						// an instance of the dynamic type we can reference here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("dst = dst[(*%s)(nil).SizeBytes()*(%s):]\n", t.Name, lenExpr)
					}
					return
				}

				g.emit("for idx := 0; idx < %s; idx++ {\n", lenExpr)
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
						// We don't have an instance of the dynamic type we can
						// reference here (since the version in this struct is
						// anonymous). Use a typed nil pointer to call
						// SizeBytes() instead.
						g.shiftDynamic("src", fmt.Sprintf("(*%s)(nil)", t.Name))
						g.recordPotentiallyNonPackedField(fmt.Sprintf("(*%s)(nil)", t.Name))
					}
					return
				}
				g.unmarshalScalar(g.fieldAccessor(n), t.Name, "src", "")
			},
			selector: func(n, tX, tSel *ast.Ident) {
				if n.Name == "_" {
					g.emit("// Padding: %s ~= src[:sizeof(%s.%s)]\n", g.fieldAccessor(n), tX.Name, tSel.Name)
					g.emit("src = src[(*%s.%s)(nil).SizeBytes():]\n", tX.Name, tSel.Name)
					g.recordPotentiallyNonPackedField(fmt.Sprintf("(*%s.%s)(nil)", tX.Name, tSel.Name))
					return
				}
				g.unmarshalScalar(g.fieldAccessor(n), fmt.Sprintf("%s.%s", tX.Name, tSel.Name), "src", "")
			},
			array: func(n *ast.Ident, a *ast.ArrayType, t *ast.Ident) {
				lenExpr := g.arrayLenExpr(a)
				if n.Name == "_" {
					g.emit("// Padding: ~ copy([%s]%s(%s), src[:sizeof(%s)*%s])\n", lenExpr, t.Name, g.fieldAccessor(n), t.Name, lenExpr)
					if size, dynamic := g.scalarSize(t); !dynamic {
						g.emit("src = src[%d*(%s):]\n", size, lenExpr)
					} else {
						// We can't use shiftDynamic here because we don't have
						// an instance of the dynamic type we can referece here
						// (since the version in this struct is anonymous). Use
						// a typed nil pointer to call SizeBytes() instead.
						g.emit("src = src[(*%s)(nil).SizeBytes()*(%s):]\n", t.Name, lenExpr)
					}
					return
				}

				g.emit("for idx := 0; idx < %s; idx++ {\n", lenExpr)
				g.inIndent(func() {
					g.unmarshalScalar(fmt.Sprintf("%s[idx]", g.fieldAccessor(n)), t.Name, "src", fmt.Sprintf("%s[0]", g.fieldAccessor(n)))
				})
				g.emit("}\n")
			},
		}.dispatch)
	})
	g.emit("}\n\n")

	g.emit("// Packed implements marshal.Marshallable.Packed.\n")
	g.emit("//go:nosplit\n")
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
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fallback to MarshalBytes.\n", g.typeName())
			g.emit("%s.MarshalBytes(dst)\n", g.r)
		}
		if thisPacked {
			g.recordUsedImport("gohacks")
			g.recordUsedImport("unsafe")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if %s {\n", cond)
				g.inIndent(func() {
					g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(%s),  uintptr(%s.SizeBytes()))\n", g.r, g.r)
				})
				g.emit("} else {\n")
				g.inIndent(fallback)
				g.emit("}\n")
			} else {
				g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(%s),  uintptr(%s.SizeBytes()))\n", g.r, g.r)
			}
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.\n")
	g.emit("func (%s *%s) UnmarshalUnsafe(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fallback to UnmarshalBytes.\n", g.typeName())
			g.emit("%s.UnmarshalBytes(src)\n", g.r)
		}
		if thisPacked {
			g.recordUsedImport("gohacks")
			if cond, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if %s {\n", cond)
				g.inIndent(func() {
					g.emit("gohacks.Memmove(unsafe.Pointer(%s), unsafe.Pointer(&src[0]), uintptr(%s.SizeBytes()))\n", g.r, g.r)
				})
				g.emit("} else {\n")
				g.inIndent(fallback)
				g.emit("}\n")
			} else {
				g.emit("gohacks.Memmove(unsafe.Pointer(%s), unsafe.Pointer(&src[0]), uintptr(%s.SizeBytes()))\n", g.r, g.r)
			}
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")
	g.emit("// CopyOutN implements marshal.Marshallable.CopyOutN.\n")
	g.emit("//go:nosplit\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("hostarch")
	g.emit("func (%s *%s) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
			g.emit("buf := cc.CopyScratchBuffer(%s.SizeBytes()) // escapes: okay.\n", g.r)
			g.emit("%s.MarshalBytes(buf) // escapes: fallback.\n", g.r)
			g.emit("return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.\n")
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
			g.emitCastToByteSlice(g.r, "buf", fmt.Sprintf("%s.SizeBytes()", g.r))

			g.emit("length, err := cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.\n")
			g.emitKeepAlive(g.r)
			g.emit("return length, err\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// CopyOut implements marshal.Marshallable.CopyOut.\n")
	g.emit("//go:nosplit\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("hostarch")
	g.emit("func (%s *%s) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("return %s.CopyOutN(cc, addr, %s.SizeBytes())\n", g.r, g.r)
	})
	g.emit("}\n\n")

	g.emit("// CopyIn implements marshal.Marshallable.CopyIn.\n")
	g.emit("//go:nosplit\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("hostarch")
	g.emit("func (%s *%s) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to UnmarshalBytes.\n", g.typeName())
			g.emit("buf := cc.CopyScratchBuffer(%s.SizeBytes()) // escapes: okay.\n", g.r)
			g.emit("length, err := cc.CopyInBytes(addr, buf) // escapes: okay.\n")
			g.emit("// Unmarshal unconditionally. If we had a short copy-in, this results in a\n")
			g.emit("// partially unmarshalled struct.\n")
			g.emit("%s.UnmarshalBytes(buf) // escapes: fallback.\n", g.r)
			g.emit("return length, err\n")
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
			g.emitCastToByteSlice(g.r, "buf", fmt.Sprintf("%s.SizeBytes()", g.r))

			g.emit("length, err := cc.CopyInBytes(addr, buf) // escapes: okay.\n")
			g.emitKeepAlive(g.r)
			g.emit("return length, err\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// WriteTo implements io.WriterTo.WriteTo.\n")
	g.recordUsedImport("io")
	g.emit("func (%s *%s) WriteTo(writer io.Writer) (int64, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
			g.emit("buf := make([]byte, %s.SizeBytes())\n", g.r)
			g.emit("%s.MarshalBytes(buf)\n", g.r)
			g.emit("length, err := writer.Write(buf)\n")
			g.emit("return int64(length), err\n")
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
			g.emitCastToByteSlice(g.r, "buf", fmt.Sprintf("%s.SizeBytes()", g.r))

			g.emit("length, err := writer.Write(buf)\n")
			g.emitKeepAlive(g.r)
			g.emit("return int64(length), err\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")
}

func (g *interfaceGenerator) emitMarshallableSliceForStruct(st *ast.StructType, slice *sliceAPI) {
	thisPacked := g.isStructPacked(st)

	if slice.inner {
		abortAt(g.f.Position(slice.comment.Slash), fmt.Sprintf("The ':inner' argument to '+marshal slice:%s:inner' is only applicable to newtypes on primitives. Remove it from this struct declaration.", slice.ident))
	}

	g.recordUsedImport("marshal")
	g.recordUsedImport("hostarch")

	g.emit("// Copy%sIn copies in a slice of %s objects from the task's memory.\n", slice.ident, g.typeName())
	g.emit("func Copy%sIn(cc marshal.CopyContext, addr hostarch.Addr, dst []%s) (int, error) {\n", slice.ident, g.typeName())
	g.inIndent(func() {
		g.emit("count := len(dst)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return 0, nil\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to UnmarshalBytes.\n", g.typeName())
			g.emit("buf := cc.CopyScratchBuffer(size * count)\n")
			g.emit("length, err := cc.CopyInBytes(addr, buf)\n\n")

			g.emit("// Unmarshal as much as possible, even on error. First handle full objects.\n")
			g.emit("limit := length/size\n")
			g.emit("for idx := 0; idx < limit; idx++ {\n")
			g.inIndent(func() {
				g.emit("dst[idx].UnmarshalBytes(buf[size*idx:size*(idx+1)])\n")
			})
			g.emit("}\n\n")

			g.emit("// Handle any final partial object. buf is guaranteed to be long enough for the\n")
			g.emit("// final element, but may not contain valid data for the entire range. This may\n")
			g.emit("// result in unmarshalling zero values for some parts of the object.\n")
			g.emit("if length%size != 0 {\n")
			g.inIndent(func() {
				g.emit("idx := limit\n")
				g.emit("dst[idx].UnmarshalBytes(buf[size*idx:size*(idx+1)])\n")
			})
			g.emit("}\n\n")

			g.emit("return length, err\n")
		}
		if thisPacked {
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			g.recordUsedImport("unsafe")
			if _, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !dst[0].Packed() {\n")
				g.inIndent(fallback)
				g.emit("}\n\n")
			}
			// Fast deserialization.
			g.emitCastSliceToByteSlice("&dst", "buf", "size * count")

			g.emit("length, err := cc.CopyInBytes(addr, buf)\n")
			g.emitKeepAlive("dst")
			g.emit("return length, err\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// Copy%sOut copies a slice of %s objects to the task's memory.\n", slice.ident, g.typeName())
	g.emit("func Copy%sOut(cc marshal.CopyContext, addr hostarch.Addr, src []%s) (int, error) {\n", slice.ident, g.typeName())
	g.inIndent(func() {
		g.emit("count := len(src)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return 0, nil\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
			g.emit("buf := cc.CopyScratchBuffer(size * count)\n")
			g.emit("for idx := 0; idx < count; idx++ {\n")
			g.inIndent(func() {
				g.emit("src[idx].MarshalBytes(buf[size*idx:size*(idx+1)])\n")
			})
			g.emit("}\n")
			g.emit("return cc.CopyOutBytes(addr, buf)\n")
		}
		if thisPacked {
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			g.recordUsedImport("unsafe")
			if _, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !src[0].Packed() {\n")
				g.inIndent(fallback)
				g.emit("}\n\n")
			}
			// Fast serialization.
			g.emitCastSliceToByteSlice("&src", "buf", "size * count")

			g.emit("length, err := cc.CopyOutBytes(addr, buf)\n")
			g.emitKeepAlive("src")
			g.emit("return length, err\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// MarshalUnsafe%s is like %s.MarshalUnsafe, but for a []%s.\n", slice.ident, g.typeName(), g.typeName())
	g.emit("func MarshalUnsafe%s(src []%s, dst []byte) (int, error) {\n", slice.ident, g.typeName())
	g.inIndent(func() {
		g.emit("count := len(src)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return 0, nil\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
			g.emit("for idx := 0; idx < count; idx++ {\n")
			g.inIndent(func() {
				g.emit("src[idx].MarshalBytes(dst[size*idx:(size)*(idx+1)])\n")
			})
			g.emit("}\n")
			g.emit("return size * count, nil\n")
		}
		if thisPacked {
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			g.recordUsedImport("unsafe")
			g.recordUsedImport("gohacks")
			if _, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !src[0].Packed() {\n")
				g.inIndent(fallback)
				g.emit("}\n\n")
			}
			g.emit("dst = dst[:size*count]\n")
			g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(dst)))\n")
			g.emit("return size * count, nil\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe%s is like %s.UnmarshalUnsafe, but for a []%s.\n", slice.ident, g.typeName(), g.typeName())
	g.emit("func UnmarshalUnsafe%s(dst []%s, src []byte) (int, error) {\n", slice.ident, g.typeName())
	g.inIndent(func() {
		g.emit("count := len(dst)\n")
		g.emit("if count == 0 {\n")
		g.inIndent(func() {
			g.emit("return 0, nil\n")
		})
		g.emit("}\n")
		g.emit("size := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		fallback := func() {
			g.emit("// Type %s doesn't have a packed layout in memory, fall back to UnmarshalBytes.\n", g.typeName())
			g.emit("for idx := 0; idx < count; idx++ {\n")
			g.inIndent(func() {
				g.emit("dst[idx].UnmarshalBytes(src[size*idx:size*(idx+1)])\n")
			})
			g.emit("}\n")
			g.emit("return size * count, nil\n")
		}
		if thisPacked {
			g.recordUsedImport("gohacks")
			g.recordUsedImport("reflect")
			g.recordUsedImport("runtime")
			if _, ok := g.areFieldsPackedExpression(); ok {
				g.emit("if !dst[0].Packed() {\n")
				g.inIndent(fallback)
				g.emit("}\n\n")
			}

			g.emit("src = src[:(size*count)]\n")
			g.emit("gohacks.Memmove(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), uintptr(len(src)))\n")

			g.emit("return count*size, nil\n")
		} else {
			fallback()
		}
	})
	g.emit("}\n\n")
}
