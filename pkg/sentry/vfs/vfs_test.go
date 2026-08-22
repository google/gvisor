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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
)

type releaseFilesystemType struct {
	anonFilesystemType
	release func()
}

// Release implements FilesystemType.Release.
func (fst *releaseFilesystemType) Release(context.Context) {
	fst.release()
}

func TestReleaseFilesystemTypes(t *testing.T) {
	ctx := contexttest.Context(t)
	var vfsObj VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	const name = "release-test"
	var released int
	fst := &releaseFilesystemType{release: func() {
		released++
		// Fail directly if Release holds the registry lock across callbacks.
		if !vfsObj.fsTypesMu.TryLock() {
			t.Error("Release called filesystem with fsTypesMu held")
			return
		}
		vfsObj.fsTypesMu.Unlock()
		if got := vfsObj.getFilesystemType(name); got != nil {
			t.Error("filesystem type is still registered during Release")
		}
	}}
	vfsObj.MustRegisterFilesystemType(name, fst, &RegisterFilesystemTypeOptions{})
	vfsObj.Release(ctx)
	if released != 1 {
		t.Errorf("Release callback ran %d times, want 1", released)
	}
}
