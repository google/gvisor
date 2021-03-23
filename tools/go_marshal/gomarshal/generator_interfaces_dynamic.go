// Copyright 2021 The gVisor Authors.
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

func (g *interfaceGenerator) emitMarshallableForDynamicType() {
	// The user writes their own MarshalBytes, UnmarshalBytes and SizeBytes for
	// dynamic types. Generate the rest using these definitions.

	g.emit("// Packed implements marshal.Marshallable.Packed.\n")
	g.emit("//go:nosplit\n")
	g.emit("func (%s *%s) Packed() bool {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Type %s is dynamic so it might have slice/string headers. Hence, it is not packed.\n", g.typeName())
		g.emit("return false\n")
	})
	g.emit("}\n\n")

	g.emit("// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.\n")
	g.emit("func (%s *%s) MarshalUnsafe(dst []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Type %s doesn't have a packed layout in memory, fallback to MarshalBytes.\n", g.typeName())
		g.emit("%s.MarshalBytes(dst)\n", g.r)
	})
	g.emit("}\n\n")

	g.emit("// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.\n")
	g.emit("func (%s *%s) UnmarshalUnsafe(src []byte) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Type %s doesn't have a packed layout in memory, fallback to UnmarshalBytes.\n", g.typeName())
		g.emit("%s.UnmarshalBytes(src)\n", g.r)
	})
	g.emit("}\n\n")

	g.emit("// CopyOutN implements marshal.Marshallable.CopyOutN.\n")
	g.emit("//go:nosplit\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("usermem")
	g.emit("func (%s *%s) CopyOutN(cc marshal.CopyContext, addr usermem.Addr, limit int) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
		g.emit("buf := cc.CopyScratchBuffer(%s.SizeBytes()) // escapes: okay.\n", g.r)
		g.emit("%s.MarshalBytes(buf) // escapes: fallback.\n", g.r)
		g.emit("return cc.CopyOutBytes(addr, buf[:limit]) // escapes: okay.\n")
	})
	g.emit("}\n\n")

	g.emit("// CopyOut implements marshal.Marshallable.CopyOut.\n")
	g.emit("//go:nosplit\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("usermem")
	g.emit("func (%s *%s) CopyOut(cc marshal.CopyContext, addr usermem.Addr) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("return %s.CopyOutN(cc, addr, %s.SizeBytes())\n", g.r, g.r)
	})
	g.emit("}\n\n")

	g.emit("// CopyIn implements marshal.Marshallable.CopyIn.\n")
	g.emit("//go:nosplit\n")
	g.recordUsedImport("marshal")
	g.recordUsedImport("usermem")
	g.emit("func (%s *%s) CopyIn(cc marshal.CopyContext, addr usermem.Addr) (int, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Type %s doesn't have a packed layout in memory, fall back to UnmarshalBytes.\n", g.typeName())
		g.emit("buf := cc.CopyScratchBuffer(%s.SizeBytes()) // escapes: okay.\n", g.r)
		g.emit("length, err := cc.CopyInBytes(addr, buf) // escapes: okay.\n")
		g.emit("// Unmarshal unconditionally. If we had a short copy-in, this results in a\n")
		g.emit("// partially unmarshalled struct.\n")
		g.emit("%s.UnmarshalBytes(buf) // escapes: fallback.\n", g.r)
		g.emit("return length, err\n")
	})
	g.emit("}\n\n")

	g.emit("// WriteTo implements io.WriterTo.WriteTo.\n")
	g.recordUsedImport("io")
	g.emit("func (%s *%s) WriteTo(writer io.Writer) (int64, error) {\n", g.r, g.typeName())
	g.inIndent(func() {
		g.emit("// Type %s doesn't have a packed layout in memory, fall back to MarshalBytes.\n", g.typeName())
		g.emit("buf := make([]byte, %s.SizeBytes())\n", g.r)
		g.emit("%s.MarshalBytes(buf)\n", g.r)
		g.emit("length, err := writer.Write(buf)\n")
		g.emit("return int64(length), err\n")
	})
	g.emit("}\n\n")
}
