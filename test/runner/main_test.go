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

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/test/testutil"

	_ "gvisor.dev/gvisor/runsc/cli/sentrycli"
)

func TestPrintCheckpointDir(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("ConfigureExePath: %v", err)
	}

	for _, tc := range []struct {
		name        string
		graphEngine bool
	}{
		{name: "graph", graphEngine: true},
		{name: "wire", graphEngine: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev := state.GraphEngineEnabled()
			state.EnableGraphEngine(tc.graphEngine)
			defer state.EnableGraphEngine(prev)

			root := t.TempDir()
			validDir := filepath.Join(root, "state.0")
			if err := os.MkdirAll(validDir, 0755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			f, err := os.Create(filepath.Join(validDir, checkpointFile))
			if err != nil {
				t.Fatalf("os.Create: %v", err)
			}
			w, err := statefile.NewWriter(f, nil, map[string]string{"phase": "autosave"})
			if err != nil {
				f.Close()
				t.Fatalf("statefile.NewWriter: %v", err)
			}
			ls := limits.NewLimitSet()
			ls.SetUnchecked(limits.NumberOfFiles, limits.Limit{Cur: 2048, Max: 8192})
			if _, err := state.Save(context.Background(), w, ls); err != nil {
				w.Close()
				t.Fatalf("state.Save: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("writer Close: %v", err)
			}

			emptyDir := filepath.Join(root, "state.1")
			if err := os.MkdirAll(emptyDir, 0755); err != nil {
				t.Fatalf("MkdirAll empty: %v", err)
			}
			ef, err := os.Create(filepath.Join(emptyDir, checkpointFile))
			if err != nil {
				t.Fatalf("os.Create empty: %v", err)
			}
			ef.Close()

			printCheckpointDir(validDir)
			printCheckpointDir(emptyDir)

			txtBytes, err := os.ReadFile(validDir + ".txt")
			if err != nil {
				t.Fatalf("ReadFile(.txt): %v", err)
			}
			txt := string(txtBytes)
			if !strings.Contains(txt, "phase:autosave") || !strings.Contains(txt, "LimitSet") || !strings.Contains(txt, "8192") {
				t.Errorf(".txt output missing expected metadata or state:\n%s", txt)
			}

			htmlBytes, err := os.ReadFile(validDir + ".html")
			if err != nil {
				t.Fatalf("ReadFile(.html): %v", err)
			}
			html := string(htmlBytes)
			if !strings.Contains(html, "LimitSet") || !strings.Contains(html, "8192") {
				t.Errorf(".html output missing expected state:\n%s", html)
			}

			for _, ext := range []string{".txt", ".html"} {
				if _, err := os.Stat(emptyDir + ext); !os.IsNotExist(err) {
					t.Errorf("unexpected %s created for empty checkpoint dir (err=%v)", emptyDir+ext, err)
				}
			}
		})
	}
}
