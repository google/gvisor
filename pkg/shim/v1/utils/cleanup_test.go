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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCleanupLeaseHelper(t *testing.T) {
	path := os.Getenv("GVISOR_TEST_CLEANUP_LEASE")
	if path == "" {
		t.Skip("subprocess helper")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "locked")
	var release [1]byte
	if _, err := os.Stdin.Read(release[:]); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupLeaseCoordinatesSeparateProcesses(t *testing.T) {
	path := CleanupLockPath(t.TempDir(), "same-container")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	owner := exec.CommandContext(ctx, exe, "-test.run=^TestCleanupLeaseHelper$")
	owner.Env = append(os.Environ(), "GVISOR_TEST_CLEANUP_LEASE="+path)
	release, err := owner.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	ready, err := owner.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { release.Close(); _ = owner.Process.Kill(); _ = owner.Wait() })
	if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("lease owner readiness: %q, %v", line, err)
	}
	for range 2 {
		var cleanup Cleanup
		waitCtx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := cleanup.Run(waitCtx, path, func() error { return fmt.Errorf("another process still owns cleanup") })
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("fresh cleanup instance error = %v, want lease timeout", err)
		}
	}
	if _, err := release.Write([]byte{'R'}); err != nil {
		t.Fatal(err)
	}
	if err := owner.Wait(); err != nil {
		t.Fatal(err)
	}
	var cleanup Cleanup
	if err := cleanup.Run(ctx, path, func() error { return nil }); err != nil {
		t.Fatalf("cleanup after owner exit: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed cleanup left its lock file: %v", err)
	}
}

func TestCleanupRejectsSymlinkLease(t *testing.T) {
	dir := t.TempDir()
	target, path := filepath.Join(dir, "target"), filepath.Join(dir, "lock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	var cleanup Cleanup
	if err := cleanup.Run(context.Background(), path, func() error { return nil }); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("symlink lease error = %v, want ELOOP", err)
	}
}

func TestCleanupFreshInstancesRemainSerialized(t *testing.T) {
	path := CleanupLockPath(t.TempDir(), "same-container")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var active atomic.Int32
	results := make(chan error, 16)
	for range cap(results) {
		go func() {
			var cleanup Cleanup
			results <- cleanup.Run(ctx, path, func() error {
				count := active.Add(1)
				defer active.Add(-1)
				if count != 1 {
					return fmt.Errorf("%d cleanup operations overlap", count)
				}
				time.Sleep(time.Millisecond)
				return nil
			})
		}()
	}
	for range cap(results) {
		if err := <-results; err != nil {
			t.Fatalf("serialized cleanup: %v", err)
		}
	}
}
