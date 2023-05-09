// Copyright 2021 The gVisor Authors.
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

// safemount_runner is used to test the SafeMount function. Because use of
// unix.Mount requires privilege, tests must launch this process with
// CLONE_NEWNS and CLONE_NEWUSER.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/specutils"
)

func main() {
	// The test temporary directory is the first argument.
	tempdir := os.Args[1]

	tcs := []struct {
		name     string
		testfunc func() error
	}{{
		name: "unix.Mount to folder succeeds",
		testfunc: func() error {
			dir2Path := filepath.Join(tempdir, "subdir2")
			if err := unix.Mount(filepath.Join(tempdir, "subdir"), dir2Path, "bind", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("mount: %v", err)
			}
			return unix.Unmount(dir2Path, unix.MNT_DETACH)
		},
	}, {
		// unix.Mount doesn't care whether the target is a symlink.
		name: "unix.Mount to symlink succeeds",
		testfunc: func() error {
			symlinkPath := filepath.Join(tempdir, "symlink")
			if err := unix.Mount(filepath.Join(tempdir, "subdir"), symlinkPath, "bind", unix.MS_BIND, ""); err != nil {
				return fmt.Errorf("mount: %v", err)
			}
			return unix.Unmount(symlinkPath, unix.MNT_DETACH)
		},
	}, {
		name: "SafeMount to folder succeeds",
		testfunc: func() error {
			dir2Path := filepath.Join(tempdir, "subdir2")
			if err := specutils.SafeMount(filepath.Join(tempdir, "subdir"), dir2Path, "bind", unix.MS_BIND, "", "/proc"); err != nil {
				return fmt.Errorf("SafeMount: %v", err)
			}
			return unix.Unmount(dir2Path, unix.MNT_DETACH)
		},
	}, {
		name: "SafeMount to symlink fails",
		testfunc: func() error {
			err := specutils.SafeMount(filepath.Join(tempdir, "subdir"), filepath.Join(tempdir, "symlink"), "bind", unix.MS_BIND, "", "/proc")
			if err == nil {
				return fmt.Errorf("SafeMount didn't fail, but should have")
			}
			var symErr *specutils.ErrSymlinkMount
			if !errors.As(err, &symErr) {
				return fmt.Errorf("expected SafeMount to fail with ErrSymlinkMount, but got: %v", err)
			}
			return nil
		},
	}}

	for _, tc := range tcs {
		if err := runTest(tempdir, tc.testfunc); err != nil {
			log.Fatalf("failed test %q: %v", tc.name, err)
		}
	}
}

// runTest runs testfunc with the following directory structure:
//
//	 tempdir/
//		subdir/
//		subdir2/
//		symlink --> ./subdir2
func runTest(tempdir string, testfunc func() error) error {
	// Create tempdir/subdir/.
	dirPath := filepath.Join(tempdir, "subdir")
	if err := os.Mkdir(dirPath, 0777); err != nil {
		return fmt.Errorf("os.Mkdir(%s, 0777)", dirPath)
	}
	defer os.Remove(dirPath)

	// Create tempdir/subdir2/.
	dir2Path := filepath.Join(tempdir, "subdir2")
	if err := os.Mkdir(dir2Path, 0777); err != nil {
		return fmt.Errorf("os.Mkdir(%s, 0777)", dir2Path)
	}
	defer os.Remove(dir2Path)

	// Create tempdir/symlink, which points to ./subdir2.
	symlinkPath := filepath.Join(tempdir, "symlink")
	if err := os.Symlink("./subdir2", symlinkPath); err != nil {
		return fmt.Errorf("failed to create symlink %s: %v", symlinkPath, err)
	}
	defer os.Remove(symlinkPath)

	// Run the actual test.
	return testfunc()
}
