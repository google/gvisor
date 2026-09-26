// Copyright 2026 The gVisor Authors.
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

package facts

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"strings"
	"testing"
)

type serializationFact struct {
	Value int
}

func (*serializationFact) AFact() {}

func init() {
	gob.Register((*serializationFact)(nil))
}

func TestPackageSerialize(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", `package p
	type T struct { F int; G string }
	type U struct { F int }
	func (*T) M() {}
	var hidden int
	`, 0)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := new(types.Config).Check("p", fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	typeObj := pkg.Scope().Lookup("T")
	named := typeObj.Type().(*types.Named)
	objects := []types.Object{
		nil,
		typeObj,
		named.Underlying().(*types.Struct).Field(0),
		named.Underlying().(*types.Struct).Field(1),
		pkg.Scope().Lookup("U").Type().Underlying().(*types.Struct).Field(0),
		named.Method(0),
	}
	before := NewPackage()
	for i, obj := range objects {
		before.ExportFact(obj, &serializationFact{Value: i})
	}
	before.ExportFact(pkg.Scope().Lookup("hidden"), &serializationFact{Value: -1})
	var buf bytes.Buffer
	if err := before.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	after := NewPackage()
	if err := after.ReadFrom(pkg, &buf); err != nil {
		t.Fatal(err)
	}
	if got, want := len(after.Objects), len(objects); got != want {
		t.Fatalf("deserialized %d objects, want %d", got, want)
	}
	for i, obj := range objects {
		var fact serializationFact
		if !after.ImportFact(obj, &fact) {
			t.Errorf("missing fact for %v", obj)
		} else if fact.Value != i {
			t.Errorf("fact for %v = %d, want %d", obj, fact.Value, i)
		}
	}
}

func BenchmarkSerialize(b *testing.B) {
	for _, count := range []int{64, 256} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			var src strings.Builder
			src.WriteString("package p\n")
			for i := range count {
				fmt.Fprintf(&src, "type T%d struct {\n", i)
				for j := range 8 {
					fmt.Fprintf(&src, "F%d int\n", j)
				}
				src.WriteString("}\n")
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "p.go", src.String(), 0)
			if err != nil {
				b.Fatal(err)
			}
			pkg, err := new(types.Config).Check("p", fset, []*ast.File{file}, nil)
			if err != nil {
				b.Fatal(err)
			}
			facts := NewPackage()
			for _, name := range pkg.Scope().Names() {
				fields := pkg.Scope().Lookup(name).Type().Underlying().(*types.Struct)
				for field := range fields.Fields() {
					facts.ExportFact(field, &serializationFact{})
				}
			}
			for b.Loop() {
				if err := facts.Serialize(io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
