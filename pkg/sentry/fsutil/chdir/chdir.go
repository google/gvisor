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

// Package chdir provides utilities to control the sandbox process's current
// working directory.
package chdir

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sync"
)

// chdirMu is the global mutex that synchronizes host chdir operations for the
// sandbox process.
var chdirMu sync.Mutex

// cwd is the current working directory for the sandbox process. The sandbox
// process usually runs in an empty chroot so cwd should be pointing to '/'.
// cwd is protected by chdirMu.
var cwd *os.File

// InitCWD initializes the global cwd FD. InitCWD must be called after the
// sandbox process has been configured with pivot_root(2)/chroot(2).
func InitCWD() (err error) {
	chdirMu.Lock()
	defer chdirMu.Unlock()
	if cwd != nil {
		panic("InitCWD() called twice")
	}
	cwd, err = os.Open(".")
	return
}

// DoInDir performs fn after chdir-ing to dirFD and then reverts back to the
// original CWD.
//
// Precondition: InitCWD() must have been called.
func DoInDir(dirFD int, fn func() error) error {
	chdirMu.Lock()
	defer chdirMu.Unlock()
	if cwd == nil {
		panic("DoInDir() called without calling InitCWD()")
	}

	defer func() {
		if err := unix.Fchdir(int(cwd.Fd())); err != nil {
			panic(fmt.Errorf("restoring orginial CWD failed: %v", err))
		}
	}()

	if err := unix.Fchdir(dirFD); err != nil {
		return err
	}
	return fn()
}
