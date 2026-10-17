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

package check

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"archive/zip"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/gcexportdata"
	"gvisor.dev/gvisor/tools/nogo/facts"
	"gvisor.dev/gvisor/tools/nogo/flags"
)

type factsLoadTestFact struct{}

func (*factsLoadTestFact) AFact() {}

func TestDeclaredFactsErrors(t *testing.T) {
	savedFactMap, savedBundles := flags.FactMap, flags.Bundles
	t.Cleanup(func() {
		flags.FactMap, flags.Bundles = savedFactMap, savedBundles
	})
	var malformed bytes.Buffer
	if err := gob.NewEncoder(&malformed).Encode([]struct {
		Key   string
		Value any
	}{{Value: "bad"}}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		supplied bool
		create   bool
		contents []byte
		bundles  [][]byte // A nil entry omits the package from that bundle.
		wantErr  error
		wantText string
	}{
		{name: "absent"},
		{name: "missing", supplied: true, wantErr: os.ErrNotExist},
		{name: "empty", supplied: true, create: true, wantErr: io.EOF},
		{name: "wrong_type", supplied: true, create: true, contents: malformed.Bytes(), wantText: "invalid fact payload"},
		{name: "bundle_absent", bundles: [][]byte{nil}},
		{name: "bundle_empty", bundles: [][]byte{{}}, wantErr: io.EOF},
		{name: "later_bundle_wrong_type", bundles: [][]byte{nil, malformed.Bytes()}, wantText: "invalid fact payload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dep := types.NewPackage("indirect", "indirect")
			flags.FactMap = make(map[string]string)
			flags.Bundles = nil
			if tc.supplied {
				filename := filepath.Join(t.TempDir(), "facts")
				flags.FactMap[dep.Path()] = filename
				if tc.create {
					if err := os.WriteFile(filename, tc.contents, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, contents := range tc.bundles {
				var buf bytes.Buffer
				zw := zip.NewWriter(&buf)
				if contents != nil {
					w, err := zw.Create(dep.Path())
					if err != nil {
						t.Fatal(err)
					}
					if _, err := w.Write(contents); err != nil {
						t.Fatal(err)
					}
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				filename := filepath.Join(t.TempDir(), "bundle.zip")
				if err := os.WriteFile(filename, buf.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
				flags.Bundles = append(flags.Bundles, filename)
			}
			a := &analysis.Analyzer{
				Name:      "importfact",
				FactTypes: []analysis.Fact{new(factsLoadTestFact)},
				Run: func(p *analysis.Pass) (any, error) {
					// Fact absence is allowed; input errors must fail the driver.
					_ = p.ImportPackageFact(dep, new(factsLoadTestFact))
					return nil, nil
				},
			}
			i := &importer{
				fset:      token.NewFileSet(),
				cache:     make(map[string]*importerEntry),
				analyzers: map[*analysis.Analyzer]analyzer{a: &plainAnalyzer{a}},
			}
			// An empty package exercises fact loading without SDK imports.
			_, findings, _, err := i.checkPackage("test", nil)
			if tc.wantText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("checkPackage() error = %v, want %q (findings: %v)", err, tc.wantText, findings)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("checkPackage() error = %v, want %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), dep.Path()) {
				t.Errorf("checkPackage() error = %v, want package path %q", err, dep.Path())
			}
		})
	}
}

func TestDeprecatedImportedMethods(t *testing.T) {
	for _, exported := range []bool{false, true} {
		for _, indirect := range []bool{false, true} {
			t.Run(fmt.Sprintf("exported=%t/indirect=%t", exported, indirect), func(t *testing.T) {
				analyzers := make(map[*analysis.Analyzer]analyzer)
				for a, runner := range allAnalyzers {
					if a.Name == "SA1019" {
						register(analyzers, runner)
					}
				}
				if len(analyzers) == 0 {
					t.Fatal("SA1019 is not registered")
				}
				i := &importer{
					fset:      token.NewFileSet(),
					sources:   make(map[string][]string),
					cache:     make(map[string]*importerEntry),
					imports:   make(map[string]*types.Package),
					analyzers: analyzers,
				}
				writePackage := func(path, source string) []string {
					t.Helper()
					filename := filepath.Join(t.TempDir(), "source.go")
					if err := os.WriteFile(filename, []byte(source), 0600); err != nil {
						t.Fatal(err)
					}
					i.sources[path] = []string{filename}
					return i.sources[path]
				}
				const depPath = "example.com/dep"
				writePackage(depPath, `package dep

type Value struct{}

// Deprecated: use New instead.
func (Value) Old() {}
func (Value) New() {}
`)
				if exported {
					pkg, err := i.importPackage(depPath, "")
					if err != nil {
						t.Fatal(err)
					}
					// Facts originate from source, but consumers normally use the
					// compiled type information. Method identities must agree.
					var typeData, factData bytes.Buffer
					if err := gcexportdata.Write(&typeData, i.fset, pkg); err != nil {
						t.Fatal(err)
					}
					if err := i.fastFacts(pkg).Serialize(&factData); err != nil {
						t.Fatal(err)
					}
					i.imports = make(map[string]*types.Package)
					pkg, err = gcexportdata.Read(&typeData, i.fset, i.imports, depPath)
					if err != nil {
						t.Fatal(err)
					}
					decoded := facts.NewPackage()
					if err := decoded.ReadFrom(pkg, &factData); err != nil {
						t.Fatal(err)
					}
					i.mu.Lock()
					i.cache[depPath] = &importerEntry{pkg: pkg, facts: decoded}
					i.mu.Unlock()
				}
				importPath, value := depPath, "dep.Value{}"
				if indirect {
					importPath, value = "example.com/bridge", "bridge.Value()"
					writePackage(importPath, `package bridge
import "example.com/dep"
func Value() dep.Value { return dep.Value{} }
`)
				}
				source := fmt.Sprintf(`package consumer
import %q
func use() {
    value := %s
    value.Old()
    value.New()
}
`, importPath, value)
				_, findings, _, err := i.checkPackage("example.com/consumer", writePackage("example.com/consumer", source))
				if err != nil {
					t.Fatal(err)
				}
				if len(findings) != 1 || findings[0].Category != "SA1019" || findings[0].Position.Line != 5 || !strings.Contains(findings[0].Message, "Old is deprecated") {
					t.Fatalf("findings = %v, want exactly the deprecated Old method on line 5", findings)
				}
			})
		}
	}
}
