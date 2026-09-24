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

package runsc

import (
	"strings"
	"testing"
	"time"
)

// TestDumpStacksTerminates verifies that a stack dump returns rather than
// looping forever, which would spin a core and flood the log on every SIGUSR2.
func TestDumpStacksTerminates(t *testing.T) {
	done := make(chan []byte, 1)
	go func() {
		done <- dumpStacks()
	}()

	select {
	case buf := <-done:
		if len(buf) == 0 {
			t.Fatal("dumpStacks() returned no data")
		}
		if got := string(buf); !strings.Contains(got, "goroutine ") {
			t.Errorf("dumpStacks() = %q, want a goroutine dump", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("dumpStacks() did not return; it is looping")
	}
}

// TestDumpStacksRepeatable verifies that consecutive dumps do not share a
// buffer.
func TestDumpStacksRepeatable(t *testing.T) {
	first := dumpStacks()
	second := dumpStacks()
	if len(first) == 0 || len(second) == 0 {
		t.Fatalf("dumpStacks() returned empty: %d, %d bytes", len(first), len(second))
	}
	if &first[0] == &second[0] {
		t.Error("consecutive dumpStacks() calls returned aliasing buffers")
	}
}
