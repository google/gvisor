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

package kernel

import (
	"testing"
)

// TestExistedAtCheckpointDefaultsFalse pins the property nvproxy's scoping
// rests on: a thread group that was not loaded from a state file -- a child
// forked after a restore, or a helper the checkpointer runs inside the sandbox
// -- must not be treated as holding pre-checkpoint device identities.
func TestExistedAtCheckpointDefaultsFalse(t *testing.T) {
	var tg ThreadGroup
	if tg.ExistedAtCheckpoint() {
		t.Errorf("a freshly constructed ThreadGroup reports ExistedAtCheckpoint() == true")
	}
}

func TestExistedAtCheckpointMarkAndClear(t *testing.T) {
	var tg ThreadGroup
	// StateLoad() marks every thread group it loads.
	tg.markExistedAtCheckpoint()
	if !tg.ExistedAtCheckpoint() {
		t.Fatalf("markExistedAtCheckpoint() did not take effect")
	}
	// Marking twice, as a second restore would, is idempotent.
	tg.markExistedAtCheckpoint()
	if !tg.ExistedAtCheckpoint() {
		t.Fatalf("marking twice cleared the mark")
	}
	// execve() replaces the image, and with it the user-mode driver state that
	// held the old identities.
	tg.clearExistedAtCheckpoint()
	if tg.ExistedAtCheckpoint() {
		t.Errorf("clearExistedAtCheckpoint() did not take effect")
	}
	// A thread group created after a restore and then itself checkpointed is
	// marked on the next restore.
	tg.markExistedAtCheckpoint()
	if !tg.ExistedAtCheckpoint() {
		t.Errorf("a cleared thread group could not be marked again")
	}
}
