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
	"fmt"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// NewBundle creates a temporary OCI bundle on the fly with optional custom annotations.
func NewBundle(sandboxID string, runscRuntimeDir string, enableNetworking bool, mounts []Mount, annotations map[string]string) (string, error) {
	// Create a bundle directory for the sandbox.
	bundleDir := filepath.Join(runscRuntimeDir, sandboxID)
	rootfsDir := filepath.Join(bundleDir, "rootfs")

	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create bundle directories: %w", err)
	}

	// Define the OCI Specification programmatically.
	namespaces := []specs.LinuxNamespace{
		{Type: specs.PIDNamespace},
		{Type: specs.MountNamespace},
		{Type: specs.UTSNamespace},
		{Type: specs.IPCNamespace},
	}

	if os.Geteuid() != 0 {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
	}
	if enableNetworking {
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}

	spec := &specs.Spec{
		Version:     "1.0.0",
		Annotations: annotations,
		Root: &specs.Root{
			Path: "rootfs",
			// The root filesystem is read-only for now. We can add support for
			// writable rootfs later if needed.
			Readonly: true,
		},
		Process: &specs.Process{
			Terminal: false,
			User:     specs.User{UID: 0, GID: 0},
			// Keeps the sandbox alive on the background.
			Args: []string{"sleep", "infinity"},
			Cwd:  "/",
			Env:  []string{"PATH=/bin:/usr/bin:/usr/local/bin"},
		},
		Mounts: []specs.Mount{
			// Mandatory Linux API Filesystems
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		},
		// enable basic namespaces for gVisor.
		Linux: &specs.Linux{
			Namespaces: namespaces,
		},
	}

	if os.Geteuid() != 0 {
		spec.Linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Geteuid()), Size: 1},
		}
		spec.Linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getegid()), Size: 1},
		}
	}

	// Map host binaries & libraries as readonly. The binaries will be
	// executed in gVisor sandbox, not on the host.
	for _, p := range []string{"/bin", "/usr", "/lib", "/lib64", "/etc/alternatives"} {
		if _, err := os.Stat(p); err == nil {
			opts := []string{"rbind", "ro", "nosuid", "nodev"}
			if p == "/etc/alternatives" {
				opts = []string{"rbind", "ro"}
			}
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: p,
				Type:        "bind",
				Source:      p,
				Options:     opts,
			})
		}
	}

	// Add custom mounts. Custom mounts overriding default host mounts create duplicate OCI
	// entries. The later entry overrides the earlier one, as expected by OCI specs.
	for _, m := range mounts {
		switch m.Type {
		case MountTypeBind:
			opts := []string{"rbind"}
			if m.ReadOnly {
				opts = append(opts, "ro")
			} else {
				opts = append(opts, "rw")
			}
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: filepath.Clean(m.Destination),
				Source:      filepath.Clean(m.Source),
				Type:        "bind",
				Options:     opts,
			})
		case MountTypeTmpfs:
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: filepath.Clean(m.Destination),
				Source:      "tmpfs",
				Type:        "tmpfs",
			})
		}
	}

	// Write the spec to config.json
	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Create(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to create config.json: %w", err)
	}
	defer configFile.Close()

	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(spec); err != nil {
		return "", fmt.Errorf("failed to encode config.json: %w", err)
	}

	return bundleDir, nil
}
