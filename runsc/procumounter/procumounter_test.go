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

// Package procumounter_test tests the gvisor-proc-umounter sidecar binary.
package procumounter_test

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// childEnv makes this test binary act as the parent of the umounter, from
// within new user and mount namespaces. Its value is "sync" or "nosync".
const childEnv = "PROCUMOUNTER_TEST_CHILD"

func TestMain(m *testing.M) {
	if mode := os.Getenv(childEnv); mode != "" {
		if err := runChild(mode == "sync"); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runChild mounts a tmpfs, runs the umounter on it, and checks that the tmpfs
// is unmounted iff `sync` is true.
func runChild(sync bool) error {
	dir, err := os.MkdirTemp("", "procumounter")
	if err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("cannot make mounts private: %w", err)
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("cannot mount tmpfs: %w", err)
	}
	// The marker only exists while the tmpfs is mounted.
	marker := filepath.Join(dir, "marker")
	if err := os.WriteFile(marker, nil, 0644); err != nil {
		return err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.Command(os.Args[1], dir)
	cmd.ExtraFiles = []*os.File{r} // FD 3.
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	r.Close()
	if sync {
		if _, err := w.Write([]byte{0}); err != nil {
			return err
		}
	}
	w.Close()
	err = cmd.Wait()
	_, statErr := os.Stat(marker)
	mounted := statErr == nil
	switch {
	case sync && err != nil:
		return fmt.Errorf("umounter failed: %w", err)
	case sync && mounted:
		return fmt.Errorf("%q is still mounted", dir)
	case !sync && err == nil:
		return fmt.Errorf("umounter succeeded without a sync byte")
	case !sync && !mounted:
		return fmt.Errorf("%q was unmounted without a sync byte", dir)
	}
	return nil
}

func umounterPath(t *testing.T) string {
	t.Helper()
	path, err := testutil.FindFile("runsc/procumounter/gvisor-proc-umounter")
	if err != nil {
		t.Fatalf("cannot find gvisor-proc-umounter binary: %v", err)
	}
	return path
}

// TestUmounterFitsInOnePage verifies that the compiled gvisor-proc-umounter
// binary fits in a single 4KiB page.
func TestUmounterFitsInOnePage(t *testing.T) {
	const maxSize = 4096
	st, err := os.Stat(umounterPath(t))
	if err != nil {
		t.Fatalf("cannot stat gvisor-proc-umounter: %v", err)
	}
	if st.Size() > maxSize {
		t.Errorf("gvisor-proc-umounter is %d bytes, which does not fit in a single %d-byte page", st.Size(), maxSize)
	}
}

// TestUmounterIsStatic verifies that gvisor-proc-umounter needs no dynamic
// loader, which is not available in the chroots it runs in.
func TestUmounterIsStatic(t *testing.T) {
	binary, err := elf.Open(umounterPath(t))
	if err != nil {
		t.Fatalf("cannot open gvisor-proc-umounter: %v", err)
	}
	defer binary.Close()
	for _, prog := range binary.Progs {
		if prog.Type == elf.PT_INTERP {
			t.Errorf("gvisor-proc-umounter has a PT_INTERP segment")
		}
	}
}

func TestUmounter(t *testing.T) {
	path, err := filepath.Abs(umounterPath(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, sync := range []bool{true, false} {
		t.Run(fmt.Sprintf("sync=%t", sync), func(t *testing.T) {
			mode := "nosync"
			if sync {
				mode = "sync"
			}
			cmd := exec.Command("/proc/self/exe", path)
			cmd.Env = append(os.Environ(), childEnv+"="+mode)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:  unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
				GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				if errors.Is(err, unix.EPERM) {
					t.Skipf("cannot create user and mount namespaces: %v", err)
				}
				t.Fatalf("child failed: %v\n%s", err, out)
			}
		})
	}
}
