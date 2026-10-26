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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/runsc/sandbox"
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
