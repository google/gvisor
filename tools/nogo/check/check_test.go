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
	"archive/zip"
	"bytes"
	"encoding/gob"
	"errors"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis"
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
