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
	"time"

	"golang.org/x/sys/unix"
)

// TestLoadOfADestroyedContainerLeavesNoLockFile checks that loading a
// container that was destroyed doesn't make its lock file again.
func TestLoadOfADestroyedContainerLeavesNoLockFile(t *testing.T) {
	s := StateFile{RootDir: t.TempDir(), ID: FullID{SandboxID: "gone", ContainerID: "gone"}}
	var c Container
	if err := s.load(&c, LoadOpts{}); !os.IsNotExist(err) {
		t.Fatalf("load() = %v, want an error for which os.IsNotExist is true", err)
	}
	if _, err := os.Stat(s.lockPath()); !os.IsNotExist(err) {
		t.Errorf("load() made lock file %q: %v", s.lockPath(), err)
	}
}

// TestLockOfARemovedLockFile checks that a command waiting for the lock of a
// lock file that Destroy removes ends up with the lock on the lock file that
// is at the lock path, or with none for a container that must exist.
func TestLockOfARemovedLockFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lock     func(*StateFile) error
		wantGone bool
	}{
		{name: "lock", lock: (*StateFile).lock},
		{name: "lockExisting", lock: (*StateFile).lockExisting, wantGone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := FullID{SandboxID: "sb", ContainerID: "sb"}
			destroyer := StateFile{RootDir: t.TempDir(), ID: id}
			if err := destroyer.lock(); err != nil {
				t.Fatal(err)
			}
			waiter := StateFile{RootDir: destroyer.RootDir, ID: id}
			errs := make(chan error, 1)
			go func() { errs <- tc.lock(&waiter) }()
			// Let the waiter open the lock file and wait for its lock, then
			// remove the file, as Destroy does, and let go of the lock.
			time.Sleep(100 * time.Millisecond)
			if err := os.Remove(destroyer.lockPath()); err != nil {
				t.Fatal(err)
			}
			destroyer.UnlockOrDie()
			err := <-errs
			if tc.wantGone {
				if !os.IsNotExist(err) {
					t.Fatalf("lockExisting() = %v, want an error for which os.IsNotExist is true", err)
				}
				if _, err := os.Stat(destroyer.lockPath()); !os.IsNotExist(err) {
					t.Errorf("lockExisting() made lock file %q: %v", destroyer.lockPath(), err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer waiter.UnlockOrDie()
			// A command that opens the lock file now, as lock does, can't
			// take the lock while the waiter holds it.
			f, err := os.OpenFile(destroyer.lockPath(), os.O_RDONLY|os.O_CREATE, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != unix.EWOULDBLOCK {
				t.Errorf("flock(LOCK_EX|LOCK_NB) of the lock file = %v, want %v", err, unix.EWOULDBLOCK)
			}
		})
	}
}
