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
	"os"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

func TestSpec(t *testing.T) {
	for _, netMode := range []sandbox.NetworkMode{sandbox.NetworkModeNone, sandbox.NetworkModeHost, sandbox.NetworkModeSandbox} {
		t.Run(string(netMode), func(t *testing.T) {
			spec, err := sandbox.DebugSpec(sandbox.WithNetwork(netMode))
			if err != nil {
				t.Fatalf("DebugSpec(netMode=%v) failed: %v", netMode, err)
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
			if netMode == sandbox.NetworkModeSandbox {
				expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
			}
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.MountNamespace})
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.UTSNamespace})
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.IPCNamespace})
			if os.Geteuid() != 0 {
				expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
			}

			if len(spec.Linux.Namespaces) != len(expectedNamespaces) {
				t.Errorf("netMode=%v: Namespaces length = %d, want %d. Got: %+v, Want: %+v", netMode, len(spec.Linux.Namespaces), len(expectedNamespaces), spec.Linux.Namespaces, expectedNamespaces)
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
				t.Errorf("netMode=%v: spec.Linux.Namespaces=%+v, want: %+v", netMode, spec.Linux.Namespaces, expectedNamespaces)
			}
		})
	}
}

func TestSpecMountNormalization(t *testing.T) {
	spec, err := sandbox.DebugSpec(
		sandbox.WithMount(
			sandbox.Mount{
				Source:      "/tmp/foo/../bar",
				Destination: "/mnt/foo/./bar",
				Type:        sandbox.MountTypeBind,
			},
			sandbox.Mount{
				Destination: "/mnt/baz/..",
				Type:        sandbox.MountTypeTmpfs,
			},
		),
	)
	if err != nil {
		t.Fatalf("DebugSpec failed: %v", err)
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

func TestSpecEnv(t *testing.T) {
	spec, err := sandbox.DebugSpec(sandbox.WithEnv("TEST_VAR=A", "TEST_VAR=B"))
	if err != nil {
		t.Fatalf("DebugSpec failed: %v", err)
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

func TestSpecWorkingDir(t *testing.T) {
	customCwd := "/custom/absolute/path"

	spec, err := sandbox.DebugSpec(sandbox.WithWorkingDir(customCwd))
	if err != nil {
		t.Fatalf("DebugSpec failed: %v", err)
	}

	if spec.Process.Cwd != customCwd {
		t.Errorf("spec.Process.Cwd = %q, want %q", spec.Process.Cwd, customCwd)
	}
}
