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

package sandbox_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

func TestNewBundle(t *testing.T) {
	for _, enableNetworking := range []bool{false, true} {
		t.Run(t.Name(), func(t *testing.T) {
			tempDir := t.TempDir()
			sandboxID := "test-sandbox"
			bundleDir, err := sandbox.NewBundle(sandbox.BundleConfig{
				ID:               sandboxID,
				RuntimeDir:       tempDir,
				EnableNetworking: enableNetworking,
			})
			if err != nil {
				t.Fatalf("NewBundle(enableNet=%v) failed: %v", enableNetworking, err)
			}
			defer os.RemoveAll(bundleDir)
			expectedBundleDir := filepath.Join(tempDir, sandboxID)
			if bundleDir != expectedBundleDir {
				t.Fatalf("NewBundle(%v, %v) = %q, want %q", sandboxID, tempDir, bundleDir, expectedBundleDir)
			}

			configPath := filepath.Join(bundleDir, "config.json")
			configFile, err := os.Open(configPath)
			if err != nil {
				t.Fatalf("failed to open config.json: %v", err)
			}
			defer configFile.Close()

			var spec specs.Spec
			if err := json.NewDecoder(configFile).Decode(&spec); err != nil {
				t.Fatalf("failed to decode config.json: %v", err)
			}

			if spec.Version != "1.0.0" {
				t.Errorf("spec.Version = %q, want %q", spec.Version, "1.0.0")
			}
			if spec.Root == nil || spec.Root.Path != "rootfs" {
				t.Errorf("spec.Root.Path is not 'rootfs', got: %+v", spec.Root)
			}
			if spec.Root.Readonly {
				t.Errorf("spec.Root.Readonly is true, want false")
			}
			if spec.Linux == nil {
				t.Fatalf("spec.Linux is nil")
			}

			var expectedNamespaces []specs.LinuxNamespace
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.PIDNamespace})
			if enableNetworking {
				expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
			}
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.MountNamespace})
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.UTSNamespace})
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.IPCNamespace})
			if os.Geteuid() != 0 {
				expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
			}

			if len(spec.Linux.Namespaces) != len(expectedNamespaces) {
				t.Errorf("enableNetworking=%v: Namespaces length = %d, want %d. Got: %+v, Want: %+v", enableNetworking, len(spec.Linux.Namespaces), len(expectedNamespaces), spec.Linux.Namespaces, expectedNamespaces)
			}
			namespaceComparator := func(a, b specs.LinuxNamespace) int {
				if a.Type == b.Type && a.Path == b.Path {
					return 0
				}
				if a.Type < b.Type || a.Path < b.Path {
					return -1
				}
				return 1
			}
			slices.SortFunc(spec.Linux.Namespaces, namespaceComparator)
			slices.SortFunc(expectedNamespaces, namespaceComparator)
			if !slices.Equal(spec.Linux.Namespaces, expectedNamespaces) {
				t.Errorf("enableNetworking=%v: spec.Linux.Namespaces=%+v, want: %+v", enableNetworking, spec.Linux.Namespaces, expectedNamespaces)
			}
		})
	}
}

func TestNewBundleNormalization(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox"

	mounts := []sandbox.Mount{
		{
			Source:      "/tmp/foo/../bar",
			Destination: "/mnt/foo/./bar",
			Type:        sandbox.MountTypeBind,
		},
		{
			Destination: "/mnt/baz/..",
			Type:        sandbox.MountTypeTmpfs,
		},
	}

	bundleDir, err := sandbox.NewBundle(sandbox.BundleConfig{
		ID:         sandboxID,
		RuntimeDir: tempDir,
		Mounts:     mounts,
	})
	if err != nil {
		t.Fatalf("NewBundle failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Open(configPath)
	if err != nil {
		t.Fatalf("failed to open config.json: %v", err)
	}
	defer configFile.Close()

	var spec specs.Spec
	if err := json.NewDecoder(configFile).Decode(&spec); err != nil {
		t.Fatalf("failed to decode config.json: %v", err)
	}

	var foundBind, foundTmpfs bool
	for _, m := range spec.Mounts {
		if m.Type == "bind" && m.Destination == "/mnt/foo/bar" {
			foundBind = true
			if m.Source != "/tmp/bar" {
				t.Errorf("bind source = %q, want %q", m.Source, "/tmp/bar")
			}
		}
		if m.Type == "tmpfs" && m.Destination == "/mnt" {
			foundTmpfs = true
		}
	}

	if !foundBind {
		t.Errorf("failed to find normalized bind mount '/mnt/foo/bar'")
	}
	if !foundTmpfs {
		t.Errorf("failed to find normalized tmpfs mount '/mnt'")
	}
}

func TestNewBundleWithAnnotations(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox-annotations"
	annotations := map[string]string{
		"dev.gvisor.tar.rootfs.upper": "/tmp/test.tar",
	}
	bundleDir, err := sandbox.NewBundle(sandbox.BundleConfig{
		ID:          sandboxID,
		RuntimeDir:  tempDir,
		Annotations: annotations,
	})
	if err != nil {
		t.Fatalf("NewBundle failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Open(configPath)
	if err != nil {
		t.Fatalf("failed to open config.json: %v", err)
	}
	defer configFile.Close()

	var spec specs.Spec
	if err := json.NewDecoder(configFile).Decode(&spec); err != nil {
		t.Fatalf("failed to decode config.json: %v", err)
	}

	if val, ok := spec.Annotations["dev.gvisor.tar.rootfs.upper"]; !ok || val != "/tmp/test.tar" {
		t.Errorf("expected annotation 'dev.gvisor.tar.rootfs.upper' with value '/tmp/test.tar', got spec.Annotations: %+v", spec.Annotations)
	}
}

func TestNewBundleEnv(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox-env"

	env := []string{"TEST_VAR=A", "TEST_VAR=B"}

	bundleDir, err := sandbox.NewBundle(sandbox.BundleConfig{
		ID:         sandboxID,
		RuntimeDir: tempDir,
		Env:        env,
	})
	if err != nil {
		t.Fatalf("NewBundle failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Open(configPath)
	if err != nil {
		t.Fatalf("failed to open config.json: %v", err)
	}
	defer configFile.Close()

	var spec specs.Spec
	if err := json.NewDecoder(configFile).Decode(&spec); err != nil {
		t.Fatalf("failed to decode config.json: %v", err)
	}

	expectedEnv := []string{
		"PATH=/bin:/usr/bin:/usr/local/bin",
		"TEST_VAR=A",
		"TEST_VAR=B",
	}

	// Verify default env vars
	if !slices.Equal(spec.Process.Env, expectedEnv) {
		t.Errorf("spec.Process.Env = %+v, want %+v", spec.Process.Env, expectedEnv)
	}
}

func TestNewBundleWorkingDir(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox-cwd"

	customCwd := "/custom/absolute/path"

	bundleDir, err := sandbox.NewBundle(sandbox.BundleConfig{
		ID:         sandboxID,
		RuntimeDir: tempDir,
		WorkingDir: customCwd,
	})

	if err != nil {
		t.Fatalf("NewBundle failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Open(configPath)
	if err != nil {
		t.Fatalf("failed to open config.json: %v", err)
	}
	defer configFile.Close()

	var spec specs.Spec
	if err := json.NewDecoder(configFile).Decode(&spec); err != nil {
		t.Fatalf("failed to decode config.json: %v", err)
	}

	if spec.Process.Cwd != customCwd {
		t.Errorf("spec.Process.Cwd = %q, want %q", spec.Process.Cwd, customCwd)
	}
}

func TestNewBundleUserNamespace(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox-userns"

	// Mock the SUDO environment variables
	t.Setenv("SUDO_UID", "2000")
	t.Setenv("SUDO_GID", "2001")

	bundleDir, err := sandbox.NewBundle(sandbox.BundleConfig{
		ID:          sandboxID,
		RuntimeDir:  tempDir,
		UID:         1000,
		GID:         1001,
		UnshareUser: true,
	})
	if err != nil {
		t.Fatalf("NewBundle failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Open(configPath)
	if err != nil {
		t.Fatalf("failed to open config.json: %v", err)
	}
	defer configFile.Close()

	var spec specs.Spec
	if err := json.NewDecoder(configFile).Decode(&spec); err != nil {
		t.Fatalf("failed to decode config.json: %v", err)
	}

	// 1. Verify spec.Process.User matches 1000:1001
	if spec.Process.User.UID != 1000 || spec.Process.User.GID != 1001 {
		t.Errorf("spec.Process.User = %d:%d, want 1000:1001", spec.Process.User.UID, spec.Process.User.GID)
	}

	// 2. Verify UserNamespace is present in spec.Linux.Namespaces
	foundUserNS := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			foundUserNS = true
			break
		}
	}
	if !foundUserNS {
		t.Errorf("expected UserNamespace in spec.Linux.Namespaces, got: %+v", spec.Linux.Namespaces)
	}

	// 3. Verify spec.Linux.UIDMappings bounds container 1000 -> host 2000
	if len(spec.Linux.UIDMappings) == 0 {
		t.Fatalf("expected spec.Linux.UIDMappings to have at least 1 entry")
	}
	foundUIDMapping := false
	for _, m := range spec.Linux.UIDMappings {
		if m.ContainerID == 1000 && m.HostID == 2000 && m.Size == 1 {
			foundUIDMapping = true
			break
		}
	}
	if !foundUIDMapping {
		t.Errorf("expected UIDMapping {ContainerID: 1000, HostID: 2000, Size: 1}, got: %+v", spec.Linux.UIDMappings)
	}

	// 4. Verify spec.Linux.GIDMappings bounds container 1001 -> host 2001
	if len(spec.Linux.GIDMappings) == 0 {
		t.Fatalf("expected spec.Linux.GIDMappings to have at least 1 entry")
	}
	foundGIDMapping := false
	for _, m := range spec.Linux.GIDMappings {
		if m.ContainerID == 1001 && m.HostID == 2001 && m.Size == 1 {
			foundGIDMapping = true
			break
		}
	}
	if !foundGIDMapping {
		t.Errorf("expected GIDMapping {ContainerID: 1001, HostID: 2001, Size: 1}, got: %+v", spec.Linux.GIDMappings)
	}
}
