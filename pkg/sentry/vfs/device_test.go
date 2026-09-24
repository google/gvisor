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

package vfs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/contexttest"
)

func TestGetSharedDynamicCharDevMajor(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	first, err := vfsObj.GetSharedDynamicCharDevMajor(CheckpointDeviceMajorKey)
	if err != nil {
		t.Fatalf("GetSharedDynamicCharDevMajor(%d) failed: %v", CheckpointDeviceMajorKey, err)
	}
	// Repeated allocations for the same key must return the same major number
	// without consuming additional ones; in particular, many more allocations
	// than the number of dynamic major numbers available must succeed.
	for i := 0; i < 1000; i++ {
		got, err := vfsObj.GetSharedDynamicCharDevMajor(CheckpointDeviceMajorKey)
		if err != nil {
			t.Fatalf("GetSharedDynamicCharDevMajor(%d) failed after %d calls: %v", CheckpointDeviceMajorKey, i+1, err)
		}
		if got != first {
			t.Fatalf("GetSharedDynamicCharDevMajor(%d) = %d, want %d", CheckpointDeviceMajorKey, got, first)
		}
	}

	// Distinct keys must get distinct major numbers.
	second, err := vfsObj.GetSharedDynamicCharDevMajor(FSCheckpointDeviceMajorKey)
	if err != nil {
		t.Fatalf("GetSharedDynamicCharDevMajor(%d) failed: %v", FSCheckpointDeviceMajorKey, err)
	}
	if second == first {
		t.Errorf("GetSharedDynamicCharDevMajor(%d) = %d, want != %d", FSCheckpointDeviceMajorKey, second, first)
	}

	// Shared major numbers must not be handed out by
	// GetDynamicCharDevMajor().
	for {
		major, err := vfsObj.GetDynamicCharDevMajor()
		if err != nil {
			break
		}
		if major == first || major == second {
			t.Fatalf("GetDynamicCharDevMajor() = %d, which is already reserved for a shared key", major)
		}
	}
}
