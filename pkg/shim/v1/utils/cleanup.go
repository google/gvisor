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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// CleanupLockPath is outside container state removed by runsc delete.
func CleanupLockPath(root, id string) string {
	return filepath.Join(root, ".shim-rootfs-cleanup", fmt.Sprintf("%x", sha256.Sum256([]byte(id))))
}

type cleanupCall struct {
	done chan struct{}
	err  error
}

// Cleanup bounds waits while sharing one in-flight operation per resource.
type Cleanup struct {
	mu      sync.Mutex
	pending map[string]*cleanupCall
}

// Run lets canceled callers retry without starting another blocked worker.
func (c *Cleanup) Run(ctx context.Context, key string, fn func() error) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	call := c.pending[key]
	if call == nil {
		call = &cleanupCall{done: make(chan struct{})}
		if c.pending == nil {
			c.pending = make(map[string]*cleanupCall)
		}
		c.pending[key] = call
		go func() {
			err := runLockedCleanup(ctx, key, fn)
			c.mu.Lock()
			call.err = err
			delete(c.pending, key)
			close(call.done)
			c.mu.Unlock()
		}()
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.err
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func runLockedCleanup(ctx context.Context, path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		for {
			err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if err == nil {
				break
			}
			if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
				file.Close()
				return err
			}
			select {
			case <-ctx.Done():
				file.Close()
				return context.Cause(ctx)
			case <-ticker.C:
			}
		}
		owned, statErr := file.Stat()
		current, pathErr := os.Lstat(path)
		if statErr != nil {
			file.Close()
			return statErr
		}
		if pathErr != nil || !os.SameFile(owned, current) {
			file.Close()
			continue
		}
		defer file.Close()
		defer func() {
			// Waiters on an unlinked inode re-open and verify the current lock.
			if current, err := os.Lstat(path); err == nil && os.SameFile(owned, current) {
				_ = os.Remove(path)
			}
		}()
		if err := context.Cause(ctx); err != nil {
			return err
		}
		return fn()
	}
}
