// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeOptionsRoundTrip(t *testing.T) {
	// Not valid protobuf, but these helpers only move opaque bytes around.
	want := []byte("\x0a\x04runc\x12\x03foo")

	bundle := t.TempDir()
	got, err := DrainRuntimeOptions(bytes.NewReader(want))
	if err != nil {
		t.Fatalf("DrainRuntimeOptions failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("DrainRuntimeOptions = %q, want %q", got, want)
	}
	if err := SaveRuntimeOptions(bundle, got); err != nil {
		t.Fatalf("SaveRuntimeOptions failed: %v", err)
	}
	got, err = ReadRuntimeOptions(bundle)
	if err != nil {
		t.Fatalf("ReadRuntimeOptions failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadRuntimeOptions = %q, want %q", got, want)
	}
}

// TestRuntimeOptionsNone checks that "containerd sent no options" is reported
// as nil at every step rather than as an error or an empty file. The sandbox
// path relies on this to tell missing options from real ones.
func TestRuntimeOptionsNone(t *testing.T) {
	bundle := t.TempDir()

	// Nothing saved yet.
	got, err := ReadRuntimeOptions(bundle)
	if err != nil {
		t.Fatalf("ReadRuntimeOptions on empty bundle failed: %v", err)
	}
	if got != nil {
		t.Errorf("ReadRuntimeOptions on empty bundle = %q, want nil", got)
	}

	// containerd closed stdin without writing anything.
	got, err = DrainRuntimeOptions(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("DrainRuntimeOptions on empty input failed: %v", err)
	}
	if got != nil {
		t.Errorf("DrainRuntimeOptions on empty input = %q, want nil", got)
	}

	// Saving nothing must not leave a file behind, so that a later read still
	// reports "no options" rather than an empty options message.
	if err := SaveRuntimeOptions(bundle, got); err != nil {
		t.Fatalf("SaveRuntimeOptions of nil failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundle, runtimeOptionsFilename)); !os.IsNotExist(err) {
		t.Errorf("os.Stat of options file after saving nil: got %v, want IsNotExist", err)
	}
	got, err = ReadRuntimeOptions(bundle)
	if err != nil {
		t.Fatalf("ReadRuntimeOptions failed: %v", err)
	}
	if got != nil {
		t.Errorf("ReadRuntimeOptions = %q, want nil", got)
	}
}

// TestDrainRuntimeOptionsTruncates checks that the shim bounds how much it
// reads from stdin, which is a pipe it does not control.
func TestDrainRuntimeOptionsTruncates(t *testing.T) {
	got, err := DrainRuntimeOptions(io.LimitReader(zeroReader{}, maxRuntimeOptionsSize*2))
	if err != nil {
		t.Fatalf("DrainRuntimeOptions failed: %v", err)
	}
	if len(got) != maxRuntimeOptionsSize {
		t.Errorf("len(DrainRuntimeOptions) = %d, want %d", len(got), maxRuntimeOptionsSize)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

// TestDrainRuntimeOptionsError checks that a failing stdin is reported rather
// than silently treated as "no options".
func TestDrainRuntimeOptionsError(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	w.Close()
	r.Close()
	if _, err := DrainRuntimeOptions(r); err == nil {
		t.Error("DrainRuntimeOptions on a closed pipe succeeded, want error")
	}
}
