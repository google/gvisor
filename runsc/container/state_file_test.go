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

package container

import (
	"os"
	"testing"
)

// TestLoadAfterDestroy runs Load's steps around a concurrent Destroy: the
// state file is found, then destroyed, then locked and read.
func TestLoadAfterDestroy(t *testing.T) {
	dir := t.TempDir()
	id := FullID{SandboxID: "sandbox", ContainerID: "container"}

	creator := StateFile{RootDir: dir, ID: id}
	if err := creator.LockForNew(); err != nil {
		t.Fatalf("LockForNew: %v", err)
	}
	if err := creator.SaveLocked(&Container{}); err != nil {
		t.Fatalf("SaveLocked: %v", err)
	}
	creator.UnlockOrDie()

	found, err := findContainerID(dir, id.ContainerID)
	if err != nil {
		t.Fatalf("findContainerID: %v", err)
	}

	deleter := StateFile{RootDir: dir, ID: id}
	if err := deleter.lock(BlockAcquire); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if err := deleter.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	deleter.UnlockOrDie()

	loader := StateFile{RootDir: dir, ID: found}
	if err := loader.load(&Container{}, LoadOpts{}); !os.IsNotExist(err) {
		t.Fatalf("load: got %v, want not-exist error", err)
	}
	if _, err := os.Stat(loader.lockPath()); !os.IsNotExist(err) {
		t.Errorf("lock file %q still exists after loading a destroyed container", loader.lockPath())
	}
}

// TestLoadExactMissing loads an ID that has no state file without globbing.
func TestLoadExactMissing(t *testing.T) {
	dir := t.TempDir()
	id := FullID{SandboxID: "sandbox", ContainerID: "container"}

	if _, err := Load(dir, id, LoadOpts{Exact: true}); !os.IsNotExist(err) {
		t.Fatalf("Load: got %v, want not-exist error", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Load of a missing container left %d files in %q", len(entries), dir)
	}
}
