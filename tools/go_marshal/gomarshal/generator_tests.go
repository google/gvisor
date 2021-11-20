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
	"bytes",
	"fmt",
	"reflect",
	"testing",

	"gvisor.dev/gvisor/tools/go_marshal/analysis",
}

var sliceAPIImports = []string{
	"encoding/binary",
	"gvisor.dev/gvisor/pkg/hostarch",
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

func newTestGenerator(t *ast.TypeSpec, r string) *testGenerator {
	g := &testGenerator{
		t:       t,
		r:       r,
		imports: newImportTable(),
	}

	for _, i := range standardImports {
		g.imports.add(i).markUsed()
	}
	// These imports are used if a type requests the slice API. Don't
	// mark them as used by default.
	for _, i := range sliceAPIImports {
		g.imports.add(i)
	}

	return g
}

func (g *testGenerator) typeName() string {
	return g.t.Name.Name
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
		g.emit("var x %v\n", g.typeName())
		g.emit("if x.SizeBytes() == 0 {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(\"Marshallable.SizeBytes() should not return zero\")\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTestSuspectAlignment() {
	g.inTestFunction("TestSuspectAlignment", func() {
		g.emit("var x %v\n", g.typeName())
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
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalBytes/UnmarshalBytes cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, y))\n")
		})
		g.emit("}\n")
		g.emit("yUnsafe.UnmarshalBytes(bufUnsafe)\n")
		g.emit("if !reflect.DeepEqual(x, yUnsafe) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalUnsafe/UnmarshalBytes cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, yUnsafe))\n")
		})
		g.emit("}\n\n")

		g.emit("z.UnmarshalUnsafe(buf)\n")
		g.emit("if !reflect.DeepEqual(x, z) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalBytes/UnmarshalUnsafe cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, z))\n")
		})
		g.emit("}\n")
		g.emit("zUnsafe.UnmarshalUnsafe(bufUnsafe)\n")
		g.emit("if !reflect.DeepEqual(x, zUnsafe) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalUnsafe/UnmarshalUnsafe cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, zUnsafe))\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTestMarshalUnmarshalSlicePreservesData(slice *sliceAPI) {
	for _, name := range []string{"binary", "hostarch"} {
		if !g.imports.markUsed(name) {
			panic(fmt.Sprintf("Generated test for '%s' referenced a non-existent import with local name '%s'", g.typeName(), name))
		}
	}

	g.inTestFunction("TestSafeMarshalUnmarshalSlicePreservesData", func() {
		g.emit("var x, y, yUnsafe [8]%s\n", g.typeName())
		g.emit("analysis.RandomizeValue(&x)\n\n")
		g.emit("size := (*%s)(nil).SizeBytes() * len(x)\n", g.typeName())
		g.emit("buf := bytes.NewBuffer(make([]byte, size))\n")
		g.emit("buf.Reset()\n")
		g.emit("if err := binary.Write(buf, hostarch.ByteOrder, x[:]); err != nil {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"binary.Write failed: %v\", err))\n")
		})
		g.emit("}\n")
		g.emit("bufUnsafe := make([]byte, size)\n")
		g.emit("MarshalUnsafe%s(x[:], bufUnsafe)\n\n", slice.ident)

		g.emit("UnmarshalUnsafe%s(y[:], buf.Bytes())\n", slice.ident)
		g.emit("if !reflect.DeepEqual(x, y) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across binary.Write/UnmarshalUnsafeSlice cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, y))\n")
		})
		g.emit("}\n")
		g.emit("UnmarshalUnsafe%s(yUnsafe[:], bufUnsafe)\n", slice.ident)
		g.emit("if !reflect.DeepEqual(x, yUnsafe) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across MarshalUnsafeSlice/UnmarshalUnsafeSlice cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, yUnsafe))\n")
		})
		g.emit("}\n\n")
	})
}

func (g *testGenerator) emitTestWriteToUnmarshalPreservesData() {
	g.inTestFunction("TestWriteToUnmarshalPreservesData", func() {
		g.emit("var x, y, yUnsafe %s\n", g.typeName())
		g.emit("analysis.RandomizeValue(&x)\n\n")

		g.emit("var buf bytes.Buffer\n\n")

		g.emit("x.WriteTo(&buf)\n")
		g.emit("y.UnmarshalBytes(buf.Bytes())\n\n")
		g.emit("yUnsafe.UnmarshalUnsafe(buf.Bytes())\n\n")

		g.emit("if !reflect.DeepEqual(x, y) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across WriteTo/UnmarshalBytes cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, y))\n")
		})
		g.emit("}\n")
		g.emit("if !reflect.DeepEqual(x, yUnsafe) {\n")
		g.inIndent(func() {
			g.emit("t.Fatal(fmt.Sprintf(\"Data corrupted across WriteTo/UnmarshalUnsafe cycle:\\nBefore: %+v\\nAfter: %+v\\n\", x, yUnsafe))\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTestSizeBytesOnTypedNilPtr() {
	g.inTestFunction("TestSizeBytesOnTypedNilPtr", func() {
		g.emit("var x %s\n", g.typeName())
		g.emit("sizeFromConcrete := x.SizeBytes()\n")
		g.emit("sizeFromTypedNilPtr := (*%s)(nil).SizeBytes()\n\n", g.typeName())

		g.emit("if sizeFromTypedNilPtr != sizeFromConcrete {\n")
		g.inIndent(func() {
			g.emit("t.Fatalf(\"SizeBytes() on typed nil pointer (%v) doesn't match size returned by a concrete object (%v).\\n\", sizeFromTypedNilPtr, sizeFromConcrete)\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTestBoundCheck() {
	g.inTestFunction("TestCheckedMethods", func() {
		g.emit("var x %s\n", g.typeName())
		g.emit("size := x.SizeBytes()\n")
		g.emit("b := make([]byte, size)\n\n")

		g.emit("if _, ok := x.CheckedMarshal(b[:size-1]); ok {\n")
		g.inIndent(func() {
			g.emit("t.Errorf(\"CheckedMarshal should have failed because buffer is small\")\n")
		})
		g.emit("}\n")
		g.emit("if _, ok := x.CheckedMarshal(b); !ok {\n")
		g.inIndent(func() {
			g.emit("t.Errorf(\"CheckedMarshal should have succeeded because buffer size is okay\")\n")
		})
		g.emit("}\n\n")

		g.emit("if _, ok := x.CheckedUnmarshal(b[:size-1]); ok {\n")
		g.inIndent(func() {
			g.emit("t.Errorf(\"CheckedUnmarshal should have failed because buffer is small\")\n")
		})
		g.emit("}\n")
		g.emit("if _, ok := x.CheckedUnmarshal(b); !ok {\n")
		g.inIndent(func() {
			g.emit("t.Errorf(\"CheckedUnmarshal should have succeeded because buffer size is okay\")\n")
		})
		g.emit("}\n")
	})
}

func (g *testGenerator) emitTests(slice *sliceAPI, boundCheck bool) {
	g.emitTestNonZeroSize()
	g.emitTestSuspectAlignment()
	g.emitTestMarshalUnmarshalPreservesData()
	g.emitTestWriteToUnmarshalPreservesData()
	g.emitTestSizeBytesOnTypedNilPtr()

	if slice != nil {
		g.emitTestMarshalUnmarshalSlicePreservesData(slice)
	}
	if boundCheck {
		g.emitTestBoundCheck()
	}
}

func (g *testGenerator) write(out io.Writer) error {
	return g.sourceBuffer.write(out)
}
