// Copyright The Isola Authors
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

package installer

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// lifetimeLock serializes host observation and mutations across installer pods.
type lifetimeLock struct {
	mu sync.Mutex
	// +checklocks:mu
	file *os.File
}

func (i *Installer) acquireLock() error {
	i.lock.mu.Lock()
	defer i.lock.mu.Unlock()
	if i.lock.file != nil {
		return nil
	}
	if err := checkDirectoryAncestors(i.cfg.hostPath("/run")); err != nil {
		return err
	}
	fd, err := unix.Open(i.cfg.hostPath(hostLockPath), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("opening host installer lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), hostLockPath)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("host installer lock is not a regular file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return fmt.Errorf("another installer holds the host lock: %w", err)
	}
	i.lock.file = f
	return nil
}

// Close releases host ownership after all reconciliation has stopped.
func (i *Installer) Close() error {
	i.lock.mu.Lock()
	defer i.lock.mu.Unlock()
	if i.lock.file == nil {
		return nil
	}
	err := i.lock.file.Close()
	i.lock.file = nil
	return err
}
