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
	"io"
	"strings"
)

var standardImports = []string{
	"fmt",
	"reflect",
	"testing",
	"gvisor.dev/gvisor/tools/go_marshal/analysis",
}

type testGenerator struct {
	sourceBuffer

	// The type we're serializing.
	t *ast.TypeSpec

	// Receiver argument for generated methods.
	r string

	// Imports used by generated code.
	imports *importTable

	// Import statement for the package declaring the type we generated code
	// for. We need this to construct test instances for the type, since the
	// tests aren't written in the same package.
	decl *importStmt
}

func newTestGenerator(t *ast.TypeSpec, declaration string) *testGenerator {
	if _, ok := t.Type.(*ast.StructType); !ok {
		panic(fmt.Sprintf("Attempting to generate code for a not struct type %v", t))
	}
	g := &testGenerator{
		t:       t,
		r:       receiverName(t),
		imports: newImportTable(),
	}

	for _, i := range standardImports {
		g.imports.add(i).markUsed()
	}
	g.decl = g.imports.add(declaration)
	g.decl.markUsed()

	return g
}

func (g *testGenerator) typeName() string {
	return fmt.Sprintf("%s.%s", g.decl.name, g.t.Name.Name)
}

func (g *testGenerator) forEachField(fn func(f *ast.Field)) {
	// This is guaranteed to succeed because g.t is always a struct.
	st := g.t.Type.(*ast.StructType)
	for _, field := range st.Fields.List {
		fn(field)
	}
}

func (g *testGenerator) testFuncName(base string) string {
	return fmt.Sprintf("%s%s", base, strings.Title(g.t.Name.Name))
}

func (g *testGenerator) inTestFunction(name string, body func()) {
	g.emit("func %s(t *testing.T) {\n", g.testFuncName(name))
	g.inIndent(body)
	g.emit("}\n\n")
}

func (g *testGenerator) emitTestNonZeroSize() {
	g.inTestFunction("TestSizeNonZero", func() {
		g.emit("x := &%s{}\n", g.typeName())
		g.emit("if x.SizeBytes() == 0 {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(\"Marshallable.Size() should not return zero\")\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTestSuspectAlignment() {
	g.inTestFunction("TestSuspectAlignment", func() {
		g.emit("x := %s{}\n", g.typeName())
		g.emit("analysis.AlignmentCheck(t, reflect.TypeOf(x))\n")
	})
}

func (g *testGenerator) emitTestMarshalUnmarshalPreservesData() {
	g.inTestFunction("TestSafeMarshalUnmarshalPreservesData", func() {
		g.emit("var x, y, z, yUnsafe, zUnsafe %s\n", g.typeName())
		g.emit("analysis.RandomizeValue(&x)\n\n")

		g.emit("buf := make([]byte, x.SizeBytes())\n")
		g.emit("x.MarshalBytes(buf)\n")
		g.emit("bufUnsafe := make([]byte, x.SizeBytes())\n")
		g.emit("x.MarshalUnsafe(bufUnsafe)\n\n")

		g.emit("y.UnmarshalBytes(buf)\n")
		g.emit("if !reflect.DeepEqual(x, y) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across Marshal/Unmarshal cycle:\\nBefore: %%+v\\nAfter: %%+v\\n\", x, y))\n")
		})
		g.emit("}\n")
		g.emit("yUnsafe.UnmarshalBytes(bufUnsafe)\n")
		g.emit("if !reflect.DeepEqual(x, yUnsafe) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalUnsafe/Unmarshal cycle:\\nBefore: %%+v\\nAfter: %%+v\\n\", x, yUnsafe))\n")
		})
		g.emit("}\n\n")

		g.emit("z.UnmarshalUnsafe(buf)\n")
		g.emit("if !reflect.DeepEqual(x, z) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across Marshal/UnmarshalUnsafe cycle:\\nBefore: %%+v\\nAfter: %%+v\\n\", x, z))\n")
		})
		g.emit("}\n")
		g.emit("zUnsafe.UnmarshalUnsafe(bufUnsafe)\n")
		g.emit("if !reflect.DeepEqual(x, zUnsafe) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalUnsafe/UnmarshalUnsafe cycle:\\nBefore: %%+v\\nAfter: %%+v\\n\", x, zUnsafe))\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTests() {
	g.emitTestNonZeroSize()
	g.emitTestSuspectAlignment()
	g.emitTestMarshalUnmarshalPreservesData()
}

func (g *testGenerator) write(out io.Writer) error {
	return g.sourceBuffer.write(out)
}
