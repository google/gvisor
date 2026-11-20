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

package sandboxsetup

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestMain(m *testing.M) {
	// Mounting an overlayfs requires root; re-execute in a user namespace
	// where that is available, as the container tests do.
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

// mountOverlay mounts an overlayfs under dir and returns its mount point. It
// skips the test when overlayfs cannot be mounted (e.g. no privileges).
func mountOverlay(t *testing.T, dir string) string {
	t.Helper()
	lower := filepath.Join(dir, "lower")
	upper := filepath.Join(dir, "upper")
	work := filepath.Join(dir, "work")
	merged := filepath.Join(dir, "merged")
	for _, d := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(d, 0755); err != nil {
			t.Fatalf("os.Mkdir(%q): %v", d, err)
		}
	}
	data := "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
	if err := unix.Mount("overlay", merged, "overlay", 0, data); err != nil {
		t.Skipf("cannot mount overlayfs: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(merged, unix.MNT_DETACH) })
	var statfs unix.Statfs_t
	if err := unix.Statfs(merged, &statfs); err != nil {
		t.Fatalf("Statfs(%q): %v", merged, err)
	}
	if statfs.Type != unix.OVERLAYFS_SUPER_MAGIC {
		t.Skipf("overlayfs at %q reports filesystem type %#x, want OVERLAYFS_SUPER_MAGIC", merged, statfs.Type)
	}
	return merged
}

func TestAdjustMountOptions(t *testing.T) {
	dir := t.TempDir()
	conf := &config.Config{}

	// A plain directory gets no extra options, and keeps the ones it has.
	in := []string{"rbind", "rw", "disable_file_handle_sharing"}
	if got, err := AdjustMountOptions(conf, dir, slices.Clone(in)); err != nil {
		t.Fatalf("AdjustMountOptions(%q): %v", dir, err)
	} else if !slices.Equal(got, in) {
		t.Errorf("AdjustMountOptions(%q, %q) = %q, want unchanged", dir, in, got)
	}

	// An overlayfs gets "overlayfs_stale_read" exactly once, whether or not
	// the caller already set it.
	merged := mountOverlay(t, dir)
	want := []string{"rbind", "rw", "overlayfs_stale_read"}
	for _, in := range [][]string{{"rbind", "rw"}, want} {
		if got, err := AdjustMountOptions(conf, merged, slices.Clone(in)); err != nil {
			t.Fatalf("AdjustMountOptions(%q): %v", merged, err)
		} else if !slices.Equal(got, want) {
			t.Errorf("AdjustMountOptions(%q, %q) = %q, want %q", merged, in, got, want)
		}
	}
}
