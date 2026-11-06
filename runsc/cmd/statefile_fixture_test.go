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

package cmd

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/state/statefile"
)

func writeSyntheticStatefile(t *testing.T, path string, metadata map[string]string, payload []byte) []byte {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("os.Create(%s): %v", path, err)
	}
	w, err := statefile.NewWriter(f, nil, metadata)
	if err != nil {
		f.Close()
		t.Fatalf("statefile.NewWriter: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		w.Close()
		t.Fatalf("statefile write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("statefile close: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}
	return raw
}
