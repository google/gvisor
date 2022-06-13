// Copyright 2022 The gVisor Authors.
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

package tracereplay

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// TestBasic uses a pre-generated file that is replayed into a save process.
// Then verifies that the generated file looks exactly the same as the original.
// In other words, it is doing `replay original | save new`, then checking if
// `original == new`.
func TestBasic(t *testing.T) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "tracereplay")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := filepath.Join(dir, "tracereplay.sock")

	// Start a new save server to store the replayed file. This tests that save
	// communicates with clients correctly and generates a valid file.
	s := NewSave(endpoint, filepath.Join(dir, "out"), "test-")
	defer s.Close()

	if err := s.Start(); err != nil {
		t.Fatal(err)
	}

	// Then replay the re-generated file. This tests that replay can connect to
	// a server and process the generated file.
	r := Replay{}
	r.Endpoint = endpoint

	const testdata = "tools/tracereplay/testdata/client-0001"
	r.In, err = testutil.FindFile(testdata)
	if err != nil {
		t.Fatalf("FindFile(%q): %v", testdata, err)
	}

	if err := r.Execute(); err != nil {
		t.Fatal(err)
	}

	// Wait until all messages are processed and client disconnects.
	s.WaitForNoClients()

	// The generated file must be an exact copy of the original file.
	want, err := os.ReadFile(r.In)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "out", "test-0001"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("files don't match\nwant: %s\ngot: %s", want, got)
	}
}
