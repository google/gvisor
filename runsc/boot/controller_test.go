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

package boot

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
)

func restoreOptsForStateFile(f *os.File) *sentryapi.RestoreOpts {
	return &sentryapi.RestoreOpts{FilePayload: urpc.FilePayload{Files: []*os.File{f}}}
}

func TestRestoreReadersRejectEmptyRegularStateFile(t *testing.T) {
	name := filepath.Join(t.TempDir(), "checkpoint.img")
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", name, err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer f.Close()
	_, _, _, err = getRestoreReadersForLocalCheckpointFiles(restoreOptsForStateFile(f))
	if err == nil || !strings.Contains(err.Error(), "statefile cannot be empty") {
		t.Fatalf("getRestoreReadersForLocalCheckpointFiles(empty regular file) = %v, want empty-statefile error", err)
	}
}

// TestRestoreReadersFromFIFO streams a statefile through a FIFO at most three
// bytes at a time, so reads from the FIFO return fewer bytes than requested.
func TestRestoreReadersFromFIFO(t *testing.T) {
	name := filepath.Join(t.TempDir(), "checkpoint.img")
	if err := unix.Mkfifo(name, 0600); err != nil {
		t.Fatalf("Mkfifo(%q): %v", name, err)
	}
	payload := []byte("checkpoint state streamed through a pipe")
	wantMetadata := map[string]string{"test": "fifo"}
	var encoded bytes.Buffer
	sw, err := statefile.NewWriter(&encoded, nil, wantMetadata)
	if err != nil {
		t.Fatalf("statefile.NewWriter: %v", err)
	}
	if _, err := sw.Write(payload); err != nil {
		t.Fatalf("statefile write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("statefile close: %v", err)
	}

	writeErr := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(name, os.O_WRONLY, 0)
		if err != nil {
			writeErr <- err
			return
		}
		defer w.Close()
		b := encoded.Bytes()
		for i := 0; len(b) > 0; i++ {
			// Wait for the reader to drain the FIFO, so that each read
			// gets only this chunk.
			for {
				queued, err := unix.IoctlGetInt(int(w.Fd()), linux.FIONREAD)
				if err != nil {
					writeErr <- err
					return
				}
				if queued == 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			n := min(i%3+1, len(b))
			if _, err := w.Write(b[:n]); err != nil {
				writeErr <- err
				return
			}
			b = b[n:]
		}
		writeErr <- nil
	}()

	// Blocks until the writer opens the FIFO.
	f, err := os.Open(name)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer f.Close()
	stateFile, _, _, err := getRestoreReadersForLocalCheckpointFiles(restoreOptsForStateFile(f))
	if err != nil {
		t.Fatalf("getRestoreReadersForLocalCheckpointFiles(FIFO): %v", err)
	}
	r, metadata, err := statefile.NewReader(stateFile, nil)
	if err != nil {
		t.Fatalf("statefile.NewReader: %v", err)
	}
	defer r.Close()
	if got := metadata["test"]; got != "fifo" {
		t.Errorf("metadata[%q] = %q, want %q", "test", got, "fifo")
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("state payload = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("writing statefile into FIFO: %v", err)
	}
}
