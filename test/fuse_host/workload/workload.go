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

// Binary workload runs inside a gVisor sandbox to exercise the FUSE host
// passthrough path. It mounts a FUSE filesystem using a pre-passed host FD,
// then performs filesystem operations to verify correctness.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var fuseFD = flag.Int("fd", -1, "file descriptor for the FUSE connection")

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if *fuseFD < 0 {
		return fmt.Errorf("--fd is required")
	}

	mountPoint, err := os.MkdirTemp("", "fuse-mount")
	if err != nil {
		return fmt.Errorf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountOpts := fmt.Sprintf("fd=%d,user_id=0,group_id=0,rootmode=40000", *fuseFD)
	if err := unix.Mount("fuse", mountPoint, "fuse", unix.MS_NODEV|unix.MS_NOSUID, mountOpts); err != nil {
		return fmt.Errorf("mount: %v", err)
	}
	defer unix.Unmount(mountPoint, unix.MNT_DETACH)

	// Stat root directory.
	var st unix.Stat_t
	if err := unix.Stat(mountPoint, &st); err != nil {
		return fmt.Errorf("stat root: %v", err)
	}
	if st.Mode&unix.S_IFDIR == 0 {
		return fmt.Errorf("root is not a directory: mode=%o", st.Mode)
	}

	// Read testfile.
	testfilePath := filepath.Join(mountPoint, "testfile")
	data, err := os.ReadFile(testfilePath)
	if err != nil {
		return fmt.Errorf("read testfile: %v", err)
	}
	expected := "hello from the host FUSE server\n"
	if string(data) != expected {
		return fmt.Errorf("testfile content: got %q, want %q", string(data), expected)
	}

	// Write new data to the existing file and read it back.
	writeData := "overwritten by sandbox workload\n"
	f, err := os.OpenFile(testfilePath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open testfile for write: %v", err)
	}
	if _, err := f.Write([]byte(writeData)); err != nil {
		f.Close()
		return fmt.Errorf("write testfile: %v", err)
	}
	f.Close()

	data, err = os.ReadFile(testfilePath)
	if err != nil {
		return fmt.Errorf("re-read testfile: %v", err)
	}
	if string(data) != writeData {
		return fmt.Errorf("re-read content: got %q, want %q", string(data), writeData)
	}

	return nil
}
