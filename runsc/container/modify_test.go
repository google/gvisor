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
	"errors"
	"os"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// TestModify checks that modify works on the latest saved state, even from a
// copy of the container loaded before another command saved it.
func TestModify(t *testing.T) {
	rootDir := t.TempDir()
	id := FullID{SandboxID: "sb", ContainerID: "sb"}
	cpuRes := func(quota int64) *specs.LinuxResources {
		return &specs.LinuxResources{CPU: &specs.LinuxCPU{Quota: new(quota), Period: new(uint64(100000))}}
	}
	c := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{Linux: &specs.Linux{Resources: cpuRes(25000)}},
		Status:     Running,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}
	if err := c.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	if err := c.saveLocked(); err != nil {
		t.Fatal(err)
	}
	c.Saver.UnlockOrDie()
	// requireLoadedIsCurrent checks that the file held open by s is the state
	// file, by inode number.
	requireLoadedIsCurrent := func(s *StateFile) {
		t.Helper()
		if s.loaded == nil {
			t.Fatal("state file not held open")
		}
		loaded, err := s.loaded.Stat()
		if err != nil {
			t.Fatal(err)
		}
		current, err := os.Stat(s.statePath())
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(loaded, current) {
			t.Fatal("file held open is not the state file")
		}
	}
	requireLoadedIsCurrent(&c.Saver)
	load := func() *Container {
		t.Helper()
		loaded, err := Load(rootDir, id, LoadOpts{Exact: true, SkipCheck: true})
		if err != nil {
			t.Fatal(err)
		}
		return loaded
	}
	stale := load()
	requireLoadedIsCurrent(&stale.Saver)

	if err := c.modify(func() error {
		c.changeStatus(Paused)
		c.Spec.Linux.Resources = cpuRes(50000)
		c.Sandbox.Restored = true
		return nil
	}); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}
	requireLoadedIsCurrent(&c.Saver)

	if err := stale.modify(func() error {
		if stale.Status != Paused {
			t.Errorf("status in modify() of a stale copy = %v, want %v", stale.Status, Paused)
		}
		if got := *stale.Spec.Linux.Resources.CPU.Quota; got != 50000 {
			t.Errorf("CPU quota in modify() of a stale copy = %d, want 50000", got)
		}
		if !stale.Sandbox.Restored {
			t.Errorf("Restored not set in modify() of a stale copy")
		}
		return nil
	}); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}

	// A failed modification is not saved.
	if err := c.modify(func() error {
		c.changeStatus(Running)
		return errors.New("failed")
	}); err == nil {
		t.Fatalf("modify() succeeded, want error")
	}
	if c.Saver.loaded != nil {
		t.Errorf("state file held open after failed modify()")
	}
	if got := load().Status; got != Paused {
		t.Errorf("status after failed modify() = %v, want %v", got, Paused)
	}
	if err := c.modify(func() error {
		if c.Status != Paused {
			t.Errorf("status in modify() after failed modify() = %v, want %v", c.Status, Paused)
		}
		return nil
	}); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}

	// modify does not reload if unnecessary.
	// Test this by verifying that it does *not* notice a write to the same
	// file as the state file which would cause an error on load.
	// This works because it matches on inode number, which isn't replaced by
	// such a write, whereas a real statefile write would atomically replace
	// the file, thereby changing its inode number (we checked this earlier
	// in the test via `os.SameFile`).
	c.Status = Running
	if err := os.WriteFile(c.Saver.statePath(), []byte("invalid"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := c.modify(func() error {
		if c.Status != Running {
			t.Errorf("status in modify() of an unchanged state file = %v, want %v", c.Status, Running)
		}
		c.changeStatus(Paused)
		return nil
	}); err != nil {
		t.Fatalf("modify() of an unchanged state file failed: %v", err)
	}

	// Stopped is final, even if only known in memory.
	stale.Status = Stopped
	if err := stale.modify(func() error { return nil }); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}
	if got := load().Status; got != Stopped {
		t.Errorf("status after modify() of a stopped container = %v, want %v", got, Stopped)
	}
}

// TestModifyGofer checks that `modify` takes the gofer fields from saved
// state only if the container does not know its gofer yet.
func TestModifyGofer(t *testing.T) {
	rootDir := t.TempDir()
	id := FullID{SandboxID: "sb", ContainerID: "sub"}
	c := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{},
		Status:     Created,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}
	if err := c.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	if err := c.saveLocked(); err != nil {
		t.Fatal(err)
	}
	c.Saver.UnlockOrDie()
	load := func() *Container {
		t.Helper()
		loaded, err := Load(rootDir, id, LoadOpts{Exact: true, SkipCheck: true})
		if err != nil {
			t.Fatal(err)
		}
		return loaded
	}
	// A copy loaded before the gofer starts, such as by `runsc kill`.
	stale := load()

	// The subcontainer start starts the gofer.
	if err := c.modify(func() error {
		c.GoferPid.Store(123)
		c.GoferPidIdentity = 456
		c.GoferMountConfs = specutils.GoferMountConfFlags{{Lower: specutils.Lisafs, Upper: specutils.NoOverlay}}
		return nil
	}); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}

	if err := stale.modify(func() error { return nil }); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}
	saved := load()
	if got := saved.GoferPid.Load(); got != 123 {
		t.Errorf("gofer PID after modify() of a stale copy = %d, want 123", got)
	}
	if got := saved.GoferPidIdentity; got != 456 {
		t.Errorf("gofer PID identity after modify() of a stale copy = %d, want 456", got)
	}
	if got := len(saved.GoferMountConfs); got != 1 {
		t.Errorf("gofer mount configs after modify() of a stale copy = %d, want 1", got)
	}

	// The gofer exits. `c` resets its PID in memory only, and keeps it even
	// though the saved state changed since `c` saved it.
	c.GoferPid.Store(0)
	if err := c.modify(func() error {
		if got := c.GoferPid.Load(); got != 0 {
			t.Errorf("gofer PID in modify() after the gofer exited = %d, want 0", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("modify() failed: %v", err)
	}
}

// countOpenFDs counts open file descriptors in the current process by reading /proc/self/fd.
func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestSaveLockedDurableSyncFailure verifies that when syncing the temporary file
// fails before replacement, the original state file remains readable and
// untouched, and the temporary file is removed.
func TestSaveLockedDurableSyncFailure(t *testing.T) {
	rootDir := t.TempDir()
	id := FullID{SandboxID: "sb", ContainerID: "sb"}
	c := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{},
		Status:     Running,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}

	if err := c.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	defer c.Saver.UnlockOrDie()

	// Initial successful save.
	if err := c.saveLocked(); err != nil {
		t.Fatalf("initial saveLocked failed: %v", err)
	}

	statePath := c.Saver.statePath()
	origContent, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("reading state file: %v", err)
	}

	// Inject failure into syncFile.
	oldSyncFile := syncFile
	defer func() { syncFile = oldSyncFile }()
	syncFile = func(f *os.File) error {
		return errors.New("injected sync failure")
	}

	// Attempt save with modified state.
	c.Status = Paused
	err = c.saveLocked()
	if err == nil {
		t.Fatal("saveLocked succeeded unexpectedly when syncFile failed")
	}

	// 1. Old state file remains untouched and readable.
	newContent, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("reading original state file: %v", err)
	}
	if string(newContent) != string(origContent) {
		t.Errorf("original state file was altered on sync failure")
	}

	// 2. Temporary file must be cleaned up.
	tmpPath := c.Saver.tmpStatePath()
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("tmp file %q still exists after sync failure: %v", tmpPath, err)
	}
}

// TestSaveLockedDurableDirSyncFailure verifies that when directory sync fails
// after a successful rename, SaveLocked reports an error indicating durability
// could not be guaranteed.
func TestSaveLockedDurableDirSyncFailure(t *testing.T) {
	rootDir := t.TempDir()
	id := FullID{SandboxID: "sb", ContainerID: "sb"}
	c := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{},
		Status:     Running,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}

	if err := c.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	defer c.Saver.UnlockOrDie()

	// Initial successful save.
	if err := c.saveLocked(); err != nil {
		t.Fatalf("initial saveLocked failed: %v", err)
	}

	// Inject failure into syncDir.
	oldSyncDir := syncDir
	defer func() { syncDir = oldSyncDir }()
	syncDir = func(f *os.File) error {
		return errors.New("injected dir sync failure")
	}

	c.Status = Paused
	err := c.saveLocked()
	if err == nil {
		t.Fatal("saveLocked succeeded unexpectedly when syncDir failed")
	}
	if !strings.Contains(err.Error(), "syncing state directory") {
		t.Errorf("expected dir sync error, got: %v", err)
	}

	// Rename already took place on disk; verify state file exists.
	if _, err := os.Stat(c.Saver.statePath()); err != nil {
		t.Fatalf("state file not found after rename: %v", err)
	}
}

// TestSaveLockedInodeIdentityInvariant verifies that unchangedLocked detects
// replacement when another save occurs, and reports true when unchanged.
func TestSaveLockedInodeIdentityInvariant(t *testing.T) {
	rootDir := t.TempDir()
	id := FullID{SandboxID: "sb", ContainerID: "sb"}
	c1 := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{},
		Status:     Running,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}

	if err := c1.Saver.lock(); err != nil {
		t.Fatal(err)
	}

	if err := c1.saveLocked(); err != nil {
		c1.Saver.UnlockOrDie()
		t.Fatalf("c1 saveLocked failed: %v", err)
	}

	// Directly after save, c1's loaded fd should match disk.
	if !c1.Saver.unchangedLocked() {
		c1.Saver.UnlockOrDie()
		t.Fatalf("unchangedLocked() = false for c1 immediately after save, want true")
	}

	// Second container handle simulates another process saving after c1 unlocked.
	c1.Saver.UnlockOrDie()

	c2 := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{},
		Status:     Paused,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}
	if err := c2.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	if err := c2.saveLocked(); err != nil {
		t.Fatalf("c2 saveLocked failed: %v", err)
	}
	c2.Saver.UnlockOrDie()

	// Re-acquire lock on c1 to call unchangedLocked().
	if err := c1.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	defer c1.Saver.UnlockOrDie()

	// c1's loaded handle held open the old inode; now that c2 replaced it,
	// c1 must detect that it is no longer unchanged.
	if c1.Saver.unchangedLocked() {
		t.Errorf("unchangedLocked() = true for c1 after c2 saved, want false")
	}

	// c2's loaded handle must match current state file.
	if !c2.Saver.unchangedLocked() {
		t.Errorf("unchangedLocked() = false for c2 after save, want true")
	}
}

// TestSaveLockedNoFDLeak verifies that repeated saves do not leak file descriptors.
func TestSaveLockedNoFDLeak(t *testing.T) {
	rootDir := t.TempDir()
	id := FullID{SandboxID: "sb", ContainerID: "sb"}
	c := &Container{
		ID:         id.ContainerID,
		Spec:       &specs.Spec{},
		Status:     Running,
		Sandbox:    &sandbox.Sandbox{ID: id.SandboxID},
		Saver:      StateFile{RootDir: rootDir, ID: id},
		allowWrite: true,
	}

	if err := c.Saver.lock(); err != nil {
		t.Fatal(err)
	}
	defer c.Saver.UnlockOrDie()

	// Initial warm-up save.
	if err := c.saveLocked(); err != nil {
		t.Fatalf("initial saveLocked failed: %v", err)
	}

	startFDs := countOpenFDs(t)

	// Perform 50 sequential saves.
	for i := 0; i < 50; i++ {
		c.Status = Running
		if err := c.saveLocked(); err != nil {
			t.Fatalf("saveLocked iteration %d failed: %v", i, err)
		}
	}

	endFDs := countOpenFDs(t)
	if endFDs > startFDs {
		t.Errorf("file descriptor leak detected: start FDs=%d, end FDs=%d (delta: +%d)",
			startFDs, endFDs, endFDs-startFDs)
	}
}
