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

package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestNewBundle(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox"

	bundleDir, err := NewBundle(sandboxID, tempDir, nil)
	if err != nil {
		t.Fatalf("NewBundle failed: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	expectedBundleDir := filepath.Join(tempDir, sandboxID)
	if bundleDir != expectedBundleDir {
		t.Fatalf("NewBundle(%v, %v) = %q, want %q", sandboxID, tempDir, bundleDir, expectedBundleDir)
	}

	// Verify config.json was created and contains valid OCI spec.
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
	if spec.Linux == nil {
		t.Fatalf("spec.Linux is nil")
	}

	expectedNamespaces := []specs.LinuxNamespace{
		{Type: specs.PIDNamespace},
		{Type: specs.NetworkNamespace},
		{Type: specs.MountNamespace},
		{Type: specs.UTSNamespace},
		{Type: specs.IPCNamespace},
	}

	if len(spec.Linux.Namespaces) != len(expectedNamespaces) {
		t.Errorf("Namespaces length = %d, want %d", len(spec.Linux.Namespaces), len(expectedNamespaces))
	} else {
		for i, ns := range spec.Linux.Namespaces {
			if ns.Type != expectedNamespaces[i].Type {
				t.Errorf("Namespaces[%d].Type = %q, want %q", i, ns.Type, expectedNamespaces[i].Type)
			}
		}
	}
}

func TestNewBundleWithAnnotations(t *testing.T) {
	tempDir := t.TempDir()
	sandboxID := "test-sandbox-annotations"
	annotations := map[string]string{
		"dev.gvisor.tar.rootfs.upper": "/tmp/test.tar",
	}

	bundleDir, err := NewBundle(sandboxID, tempDir, annotations)
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
