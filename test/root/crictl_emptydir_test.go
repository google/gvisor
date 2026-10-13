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

package root

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// kubeletPodsDir is where the kubelet keeps per-pod volume directories. The
// shim resolves EmptyDir volumes relative to it.
const kubeletPodsDir = "/var/lib/kubelet/pods"

// memoryEmptyDirSandbox returns a JSON config for a sandbox with the given pod
// UID and the mount annotations that the GKE admission controller sets for a
// memory-backed EmptyDir volume.
func memoryEmptyDirSandbox(name, uid, volume string) string {
	s := map[string]any{
		"metadata": map[string]string{
			"name":      name,
			"namespace": "default",
			"uid":       uid,
		},
		"annotations": map[string]string{
			"dev.gvisor.spec.mount." + volume + ".type":    "tmpfs",
			"dev.gvisor.spec.mount." + volume + ".share":   "container",
			"dev.gvisor.spec.mount." + volume + ".options": "rw,rprivate",
		},
		"linux":         map[string]string{},
		"log_directory": "/tmp",
	}
	v, err := json.Marshal(s)
	if err != nil {
		// This shouldn't happen.
		panic(err)
	}
	return string(v)
}

// mountMemoryEmptyDir lays out a memory-backed EmptyDir volume as the kubelet
// does: a tmpfs limited to sizeLimit bytes, mounted at
// /var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~empty-dir/<volume>. It
// returns the host path of the volume and a cleanup function.
func mountMemoryEmptyDir(t *testing.T, uid, volume string, sizeLimit int) (string, func()) {
	t.Helper()
	podDir := filepath.Join(kubeletPodsDir, uid)
	hostPath := filepath.Join(podDir, "volumes", "kubernetes.io~empty-dir", volume)
	if err := os.MkdirAll(hostPath, 0755); err != nil {
		t.Fatalf("creating volume directory %q: %v", hostPath, err)
	}
	if err := unix.Mount("tmpfs", hostPath, "tmpfs", 0, fmt.Sprintf("size=%d", sizeLimit)); err != nil {
		os.RemoveAll(podDir)
		t.Fatalf("mounting tmpfs at %q: %v", hostPath, err)
	}
	return hostPath, func() {
		if err := unix.Unmount(hostPath, unix.MNT_DETACH); err != nil {
			t.Logf("unmounting %q: %v", hostPath, err)
		}
		os.RemoveAll(podDir)
	}
}

// mountSizeOption returns the value of the "size=" mount option in bytes.
func mountSizeOption(opts string) (int, error) {
	for _, opt := range strings.Split(opts, ",") {
		val, ok := strings.CutPrefix(opt, "size=")
		if !ok || val == "" {
			continue
		}
		unit := 1
		switch val[len(val)-1] {
		case 'k', 'K':
			unit = 1 << 10
		case 'm', 'M':
			unit = 1 << 20
		case 'g', 'G':
			unit = 1 << 30
		}
		if unit > 1 {
			val = val[:len(val)-1]
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0, err
		}
		return n * unit, nil
	}
	return 0, fmt.Errorf("no size= option in %q", opts)
}

// TestCrictlEmptyDirSizeLimit checks that a memory-backed EmptyDir volume in a
// pod enforces the size limit of the host tmpfs that backs it. The kubelet
// mounts a size-limited tmpfs at the volume's host path. The shim replaces it
// with a sandbox-internal tmpfs and must carry the size limit over, so that
// writes beyond the limit fail with ENOSPC instead of consuming memory until
// the pod is killed.
func TestCrictlEmptyDirSizeLimit(t *testing.T) {
	crictl, cleanup, err := setup(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	const (
		volume    = "mem"
		mountPath = "/mnt/mem"
		sizeLimit = 8 << 20 // 8 MiB
	)
	uid := testutil.RandomID("")
	hostPath, unmount := mountMemoryEmptyDir(t, uid, volume, sizeLimit)
	defer unmount()

	contSpec := SimpleSpec("mem", "basic/busybox", []string{"sleep", "1000"}, map[string]any{
		"mounts": []map[string]any{
			{
				"container_path": mountPath,
				"host_path":      hostPath,
			},
		},
	})
	sbSpec := memoryEmptyDirSandbox(testutil.RandomID("emptydir"), uid, volume)
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", sbSpec, contSpec)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}
	defer func() {
		if err := crictl.StopPodAndContainers(podID, []string{contID}); err != nil {
			t.Logf("cleanup stop: %v", err)
		}
	}()

	// The volume must be a tmpfs mounted with the host's size limit.
	out, err := crictl.Exec(contID, "grep", " "+mountPath+" ", "/proc/mounts")
	if err != nil {
		t.Fatalf("reading /proc/mounts: %v", err)
	}
	fields := strings.Fields(out)
	if len(fields) < 4 || fields[2] != "tmpfs" {
		t.Fatalf("mount at %s is not a tmpfs: %q", mountPath, out)
	}
	if got, err := mountSizeOption(fields[3]); err != nil || got != sizeLimit {
		t.Errorf("mount options for %s = %q, want size=%d bytes (got %d, err %v)", mountPath, fields[3], sizeLimit, got, err)
	}

	// statfs(2) must report the size limit.
	out, err = crictl.Exec(contID, "df", "-k", mountPath)
	if err != nil {
		t.Fatalf("df %s: %v", mountPath, err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	fields = strings.Fields(lines[len(lines)-1])
	if len(fields) < 2 {
		t.Fatalf("unexpected df output: %q", out)
	}
	if got, err := strconv.Atoi(fields[1]); err != nil || got != sizeLimit>>10 {
		t.Errorf("df reports %s KiB for %s, want %d: %q", fields[1], mountPath, sizeLimit>>10, out)
	}

	// Writing past the limit must fail with ENOSPC and leave the file capped
	// at the limit.
	fill := filepath.Join(mountPath, "fill")
	script := fmt.Sprintf("dd if=/dev/zero of=%s bs=1M count=%d 2>&1; echo; stat -c %%s %s", fill, 2*sizeLimit>>20, fill)
	out, err = crictl.Exec(contID, "sh", "-c", script)
	if err != nil {
		t.Fatalf("filling %s: %v", fill, err)
	}
	if !strings.Contains(out, "No space left on device") {
		t.Errorf("writing %d MiB to %s did not fail with ENOSPC: %q", 2*sizeLimit>>20, fill, out)
	}
	fields = strings.Fields(out)
	if got, err := strconv.Atoi(fields[len(fields)-1]); err != nil || got != sizeLimit {
		t.Errorf("size of %s after filling = %s, want %d: %q", fill, fields[len(fields)-1], sizeLimit, out)
	}

	// The container must survive the failed write.
	if _, err := crictl.Exec(contID, "true"); err != nil {
		t.Errorf("container is not running after filling %s: %v", fill, err)
	}
}
