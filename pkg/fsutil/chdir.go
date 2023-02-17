// Copyright 2023 The gVisor Authors.
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

package fsutil

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

// chdirMu is the global mutex that synchronizes host chdir operations.
var chdirMu sync.Mutex

// DoInDir performs fn after chdir-ing to dirFD and then reverts back to the
// original CWD.
func DoInDir(dirFD int, fn func() error) error {
	chdirMu.Lock()
	defer chdirMu.Unlock()

	oldCWD, err := unix.Openat(unix.AT_FDCWD, ".", unix.O_PATH, 0 /* mode */)
	if err != nil {
		return err
	}

	defer func() {
		if err := unix.Fchdir(oldCWD); err != nil {
			panic(fmt.Errorf("restoring orginial CWD failed: %v", err))
		}
	}()

	if err := unix.Fchdir(dirFD); err != nil {
		return err
	}
	return fn()
}
