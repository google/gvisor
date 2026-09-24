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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestAbortFuseConnection(t *testing.T) {
	tempDir := t.TempDir()
	oldConnDir := fuseConnectionsDir
	fuseConnectionsDir = tempDir
	defer func() { fuseConnectionsDir = oldConnDir }()

	minor := uint32(319)
	connDir := filepath.Join(tempDir, fmt.Sprintf("%d", minor))
	if err := os.MkdirAll(connDir, 0755); err != nil {
		t.Fatalf("failed to create conn dir: %v", err)
	}
	abortFile := filepath.Join(connDir, "abort")
	if err := os.WriteFile(abortFile, []byte("0"), 0644); err != nil {
		t.Fatalf("failed to create abort file: %v", err)
	}

	if err := abortFuseConnection(minor); err != nil {
		t.Fatalf("abortFuseConnection failed: %v", err)
	}

	content, err := os.ReadFile(abortFile)
	if err != nil {
		t.Fatalf("failed to read abort file: %v", err)
	}
	if string(content) != "1" {
		t.Errorf("expected abort file content '1', got %q", string(content))
	}
}

func TestAbortFuseConnectionNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	oldConnDir := fuseConnectionsDir
	fuseConnectionsDir = tempDir
	defer func() { fuseConnectionsDir = oldConnDir }()

	// If the connection does not exist, it should return nil (no-op).
	if err := abortFuseConnection(999); err != nil {
		t.Errorf("expected nil error for nonexistent connection, got: %v", err)
	}
}

func TestAbortMountFuseConnectionsNonFUSE(t *testing.T) {
	tempDir := t.TempDir()
	mounts := []specs.Mount{
		{
			Source:      tempDir,
			Destination: "/data",
			Type:        "bind",
		},
		{
			Source:      "/nonexistent/path/that/does/not/exist",
			Destination: "/other",
			Type:        "bind",
		},
		{
			Source:      "",
			Destination: "/empty",
		},
	}

	// Should safely ignore non-FUSE and nonexistent mounts without error.
	if err := AbortMountFuseConnections(mounts); err != nil {
		t.Errorf("AbortMountFuseConnections returned unexpected error: %v", err)
	}
}

func TestAbortPodFuseConnectionsEmptyOrMissing(t *testing.T) {
	if err := AbortPodFuseConnections(""); err != nil {
		t.Errorf("expected nil for empty pod UID, got: %v", err)
	}
	if err := AbortPodFuseConnections("nonexistent-uid-12345"); err != nil {
		t.Errorf("expected nil for nonexistent pod UID, got: %v", err)
	}
}

func TestAbortFuseMinors(t *testing.T) {
	tempDir := t.TempDir()
	oldConnDir := fuseConnectionsDir
	fuseConnectionsDir = tempDir
	defer func() { fuseConnectionsDir = oldConnDir }()

	minor1 := uint32(101)
	minor2 := uint32(102)

	for _, minor := range []uint32{minor1, minor2} {
		connDir := filepath.Join(tempDir, fmt.Sprintf("%d", minor))
		if err := os.MkdirAll(connDir, 0755); err != nil {
			t.Fatalf("failed to create conn dir: %v", err)
		}
		abortFile := filepath.Join(connDir, "abort")
		if err := os.WriteFile(abortFile, []byte("0"), 0644); err != nil {
			t.Fatalf("failed to create abort file: %v", err)
		}
	}

	if err := AbortFuseMinors([]uint32{minor1, minor2}); err != nil {
		t.Fatalf("AbortFuseMinors failed: %v", err)
	}

	for _, minor := range []uint32{minor1, minor2} {
		abortFile := filepath.Join(tempDir, fmt.Sprintf("%d", minor), "abort")
		content, err := os.ReadFile(abortFile)
		if err != nil {
			t.Fatalf("failed to read abort file: %v", err)
		}
		if string(content) != "1" {
			t.Errorf("expected '1', got %q for minor %d", string(content), minor)
		}
	}
}

func TestFindFuseMountMinorsNonFUSE(t *testing.T) {
	tempDir := t.TempDir()
	mounts := []specs.Mount{
		{
			Source:      tempDir,
			Destination: "/data",
			Type:        "bind",
		},
		{
			Source:      "/nonexistent/path",
			Destination: "/nonexistent",
		},
		{
			Source:      "",
			Destination: "/empty",
		},
	}
	minors := FindFuseMountMinors(mounts)
	if len(minors) != 0 {
		t.Errorf("expected 0 minors for non-FUSE mounts, got %v", minors)
	}
}

func TestFindFuseMountMinors_FromMountinfo(t *testing.T) {
	tempDir := t.TempDir()
	mountinfoFile := filepath.Join(tempDir, "mountinfo")
	mountinfoContent := `36 26 0:30 / /sys rw,nosuid shared:1 - sysfs sysfs rw
2611 61 0:391 / /var/lib/kubelet/pods/pod123/volumes/kubernetes.io~csi/gcs-workspace/mount rw,relatime shared:981 - fuse zkoopmans-gke-dev-gke-bucket rw
2668 61 0:399 / /var/lib/kubelet/pods/pod123/volumes/kubernetes.io~csi/wazuh-state/mount rw,relatime shared:1173 - fuse zkoopmans-gke-dev-gke-bucket rw
`
	if err := os.WriteFile(mountinfoFile, []byte(mountinfoContent), 0644); err != nil {
		t.Fatalf("failed to write mountinfo: %v", err)
	}
	oldMountinfo := mountinfoPath
	mountinfoPath = mountinfoFile
	defer func() { mountinfoPath = oldMountinfo }()

	mounts := []specs.Mount{
		{
			Source: "/var/lib/kubelet/pods/pod123/volumes/kubernetes.io~csi/gcs-workspace/mount",
		},
		{
			Source: "/some/nonexistent/mount",
		},
	}
	minors := FindFuseMountMinors(mounts)
	if len(minors) != 1 || minors[0] != 391 {
		t.Errorf("expected minors [391], got %v", minors)
	}

	// Verify subdirectories/subpaths inside a FUSE mount are discovered.
	subpathMounts := []specs.Mount{
		{
			Source: "/var/lib/kubelet/pods/pod123/volumes/kubernetes.io~csi/gcs-workspace/mount/sub/directory",
		},
	}
	subMinors := FindFuseMountMinors(subpathMounts)
	if len(subMinors) != 1 || subMinors[0] != 391 {
		t.Errorf("expected minors [391] for subpath mount, got %v", subMinors)
	}
}

func TestFindPodCSIFuseMinors_FromMountinfo(t *testing.T) {
	tempDir := t.TempDir()
	mountinfoFile := filepath.Join(tempDir, "mountinfo")
	mountinfoContent := `36 26 0:30 / /sys rw,nosuid shared:1 - sysfs sysfs rw
2611 61 0:391 / /var/lib/kubelet/pods/pod123/volumes/kubernetes.io~csi/gcs-workspace/mount rw,relatime shared:981 - fuse zkoopmans-gke-dev-gke-bucket rw
2668 61 0:399 / /var/lib/kubelet/pods/pod123/volumes/kubernetes.io~csi/wazuh-state/mount rw,relatime shared:1173 - fuse.gcsfuse zkoopmans-gke-dev-gke-bucket rw
2670 61 0:401 / /var/lib/kubelet/pods/pod123/volume-subpaths/gcs-workspace/container1/0 rw,relatime shared:1180 - fuse zkoopmans-gke-dev-gke-bucket rw
2700 61 0:405 / /var/lib/kubelet/pods/otherpod/volumes/kubernetes.io~csi/vol/mount rw,relatime shared:1200 - fuse gcs rw
`
	if err := os.WriteFile(mountinfoFile, []byte(mountinfoContent), 0644); err != nil {
		t.Fatalf("failed to write mountinfo: %v", err)
	}
	oldMountinfo := mountinfoPath
	mountinfoPath = mountinfoFile
	defer func() { mountinfoPath = oldMountinfo }()

	minors := FindPodCSIFuseMinors("pod123")
	if len(minors) != 3 || minors[0] != 391 || minors[1] != 399 || minors[2] != 401 {
		t.Errorf("expected minors [391 399 401], got %v", minors)
	}

	otherMinors := FindPodCSIFuseMinors("otherpod")
	if len(otherMinors) != 1 || otherMinors[0] != 405 {
		t.Errorf("expected otherMinors [405], got %v", otherMinors)
	}
}

func TestFuseAbortOnTeardownAnnotation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "nil annotations",
			annotations: nil,
			want:        false,
		},
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			want:        false,
		},
		{
			name: "unrelated annotation",
			annotations: map[string]string{
				"some.other.annotation": "true",
			},
			want: false,
		},
		{
			name: "opt-in false",
			annotations: map[string]string{
				FuseAbortOnTeardownAnnotation: "false",
			},
			want: false,
		},
		{
			name: "opt-in true",
			annotations: map[string]string{
				FuseAbortOnTeardownAnnotation: "true",
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &specs.Spec{
				Annotations: tc.annotations,
			}
			got := FuseAbortOnTeardown(s, "")
			if got != tc.want {
				t.Errorf("FuseAbortOnTeardown(%+v) = %v, want %v", tc.annotations, got, tc.want)
			}
		})
	}
}

func TestFuseAbortOnTeardown_SandboxLookup(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "sandbox123"
	containerID := "container456"

	sandboxBundle := filepath.Join(tempDir, sandboxID)
	containerBundle := filepath.Join(tempDir, containerID)
	if err := os.MkdirAll(sandboxBundle, 0755); err != nil {
		t.Fatalf("failed to create sandbox bundle: %v", err)
	}
	if err := os.MkdirAll(containerBundle, 0755); err != nil {
		t.Fatalf("failed to create container bundle: %v", err)
	}

	sandboxSpec := &specs.Spec{
		Annotations: map[string]string{
			FuseAbortOnTeardownAnnotation: "true",
		},
	}
	if err := WriteSpec(sandboxBundle, sandboxSpec); err != nil {
		t.Fatalf("failed to write sandbox spec: %v", err)
	}

	containerSpec := &specs.Spec{
		Annotations: map[string]string{
			specutils.ContainerdSandboxIDAnnotation: sandboxID,
		},
	}
	if !FuseAbortOnTeardown(containerSpec, containerBundle) {
		t.Errorf("expected FuseAbortOnTeardown to return true via sandbox spec lookup")
	}
}

func TestPodUID_SandboxLookup(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "sandbox123"
	containerID := "container456"
	expectedUID := "test-pod-uid-789"

	sandboxBundle := filepath.Join(tempDir, sandboxID)
	containerBundle := filepath.Join(tempDir, containerID)
	if err := os.MkdirAll(sandboxBundle, 0755); err != nil {
		t.Fatalf("failed to create sandbox bundle: %v", err)
	}
	if err := os.MkdirAll(containerBundle, 0755); err != nil {
		t.Fatalf("failed to create container bundle: %v", err)
	}

	sandboxSpec := &specs.Spec{
		Annotations: map[string]string{
			sandboxUIDAnnotation: expectedUID,
		},
	}
	if err := WriteSpec(sandboxBundle, sandboxSpec); err != nil {
		t.Fatalf("failed to write sandbox spec: %v", err)
	}

	containerSpec := &specs.Spec{
		Annotations: map[string]string{
			specutils.ContainerdSandboxIDAnnotation: sandboxID,
		},
	}
	uid, err := PodUID(containerSpec, containerBundle)
	if err != nil {
		t.Fatalf("PodUID failed on child container: %v", err)
	}
	if uid != expectedUID {
		t.Errorf("PodUID = %q, want %q", uid, expectedUID)
	}
}

func TestAbortFuseConnection_MissingSysfs(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentDir := filepath.Join(tempDir, "missing-fusectl")
	oldDir := fuseConnectionsDir
	fuseConnectionsDir = nonExistentDir
	defer func() { fuseConnectionsDir = oldDir }()

	if err := abortFuseConnection(42); err == nil {
		t.Errorf("expected error when sysfs fusectl directory does not exist, got nil")
	}
}

func TestAbortFuseConnection_Success(t *testing.T) {
	tempDir := t.TempDir()
	connDir := filepath.Join(tempDir, "connections")
	minorDir := filepath.Join(connDir, "42")
	if err := os.MkdirAll(minorDir, 0755); err != nil {
		t.Fatalf("failed to create minor dir: %v", err)
	}
	abortFile := filepath.Join(minorDir, "abort")
	if err := os.WriteFile(abortFile, []byte("0"), 0644); err != nil {
		t.Fatalf("failed to create abort file: %v", err)
	}

	oldDir := fuseConnectionsDir
	fuseConnectionsDir = connDir
	defer func() { fuseConnectionsDir = oldDir }()

	if err := abortFuseConnection(42); err != nil {
		t.Fatalf("abortFuseConnection failed: %v", err)
	}

	content, err := os.ReadFile(abortFile)
	if err != nil {
		t.Fatalf("failed to read abort file: %v", err)
	}
	if string(content) != "1" {
		t.Errorf("expected abort file content '1', got %q", string(content))
	}
}

func TestAbortFuseConnection_ConnectionNotExist(t *testing.T) {
	tempDir := t.TempDir()
	connDir := filepath.Join(tempDir, "connections")
	if err := os.MkdirAll(connDir, 0755); err != nil {
		t.Fatalf("failed to create conn dir: %v", err)
	}

	oldDir := fuseConnectionsDir
	fuseConnectionsDir = connDir
	defer func() { fuseConnectionsDir = oldDir }()

	// If the minor dir does not exist (already closed), it should safely return nil.
	if err := abortFuseConnection(999); err != nil {
		t.Errorf("expected nil when minor directory does not exist, got %v", err)
	}
}
