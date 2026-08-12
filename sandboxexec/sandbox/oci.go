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

// defaultInitArgs is the placeholder init that keeps the sandbox alive for
// later Exec calls. The path is absolute because the sandbox may have no PATH
// to search, which does mean every sandbox needs /bin/sleep to be created.
var defaultInitArgs = []string{"/bin/sleep", "infinity"}

// baseEnv is prepended to the process environment unless SkipBaseEnv is set.
var baseEnv = []string{"PATH=/bin:/usr/bin:/usr/local/bin"}

// hostBinaryDirs are bind mounted read-only so that host binaries and
// libraries are available inside the sandbox. The binaries are executed in the
// gVisor sandbox, not on the host.
var hostBinaryDirs = []string{"/bin", "/usr", "/lib", "/lib64", "/etc/alternatives"}

// defaultRootfsDir is the bundle-relative root filesystem given to a sandbox
// that was not pointed at one of its own.
const defaultRootfsDir = "rootfs"

// bundleConfig holds configuration for creating an OCI bundle.
//
// The zero value of every field reproduces the default sandbox layout, so
// callers only need to set the fields whose defaults do not suit them.
type bundleConfig struct {
	ID               string
	RuntimeDir       string
	EnableNetworking bool
	Mounts           []Mount
	Env              []string
	Annotations      map[string]string
	WorkingDir       string
	Hostname         string

	// RootPath is the container's root filesystem. When empty, newBundle
	// creates an empty "rootfs" directory inside the bundle and uses that.
	RootPath string

	// RootReadonly mounts the container's root filesystem read-only.
	RootReadonly bool

	// User is the user the init process runs as. Defaults to 0:0.
	User *specs.User

	// Capabilities is the capability set of the init process. When nil, the
	// runtime applies its own default.
	Capabilities *specs.LinuxCapabilities

	// Namespaces are appended to the namespace set.
	Namespaces []specs.LinuxNamespace

	// UIDMappings and GIDMappings replace the default ID mappings when either
	// is non-nil.
	UIDMappings []specs.LinuxIDMapping
	GIDMappings []specs.LinuxIDMapping

	// SkipDefaultNamespaces omits the PID, mount, UTS, IPC, user and network
	// namespaces that are otherwise added automatically, along with the
	// default ID mappings that accompany the user namespace.
	SkipDefaultNamespaces bool

	// SkipDefaultMounts omits the automatic /proc and /dev mounts.
	SkipDefaultMounts bool

	// SkipHostBinaryMounts omits the read-only binds of the host's binary and
	// library directories.
	SkipHostBinaryMounts bool

	// SkipBaseEnv omits the default PATH entry otherwise prepended to Env.
	SkipBaseEnv bool
}

// ociType returns the OCI filesystem type name for t.
func (t MountType) ociType() (string, error) {
	switch t {
	case MountTypeBind:
		return "bind", nil
	case MountTypeTmpfs:
		return "tmpfs", nil
	case MountTypeProc:
		return "proc", nil
	case MountTypeSysfs:
		return "sysfs", nil
	case MountTypeDevtmpfs:
		return "devtmpfs", nil
	case MountTypeDevpts:
		return "devpts", nil
	case MountTypeCgroup:
		return "cgroupfs", nil
	}
	return "", fmt.Errorf("unknown mount type %d", t)
}

// ociMount converts m into an OCI mount entry.
func (m Mount) ociMount() (specs.Mount, error) {
	fsType, err := m.Type.ociType()
	if err != nil {
		return specs.Mount{}, err
	}
	source := m.Source
	if source != "" {
		source = filepath.Clean(source)
	}
	opts := m.Options
	if opts == nil && m.Type == MountTypeBind {
		if m.ReadOnly {
			opts = []string{"rbind", "ro"}
		} else {
			opts = []string{"rbind", "rw"}
		}
	}
	return specs.Mount{
		Destination: filepath.Clean(m.Destination),
		Source:      source,
		Type:        fsType,
		Options:     opts,
	}, nil
}

// newSpec builds the OCI runtime specification described by cfg. It only
// computes the specification; newBundle is what puts it on disk.
func newSpec(cfg bundleConfig) (*specs.Spec, error) {
	// Without an explicit root, the container gets the empty root filesystem
	// newBundle creates inside the bundle.
	rootPath := cfg.RootPath
	if rootPath == "" {
		rootPath = defaultRootfsDir
	}

	// Define the OCI Specification programmatically.
	var namespaces []specs.LinuxNamespace
	if !cfg.SkipDefaultNamespaces {
		namespaces = []specs.LinuxNamespace{
			{Type: specs.PIDNamespace},
			{Type: specs.MountNamespace},
			{Type: specs.UTSNamespace},
			{Type: specs.IPCNamespace},
		}
		if os.Geteuid() != 0 {
			namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		}
		if cfg.EnableNetworking {
			namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
		}
	}
	namespaces = append(namespaces, cfg.Namespaces...)

	user := specs.User{UID: 0, GID: 0}
	if cfg.User != nil {
		user = *cfg.User
	}

	spec := &specs.Spec{
		Version:     "1.0.0",
		Annotations: cfg.Annotations,
		Root: &specs.Root{
			Path:     rootPath,
			Readonly: cfg.RootReadonly,
		},
		Process: &specs.Process{
			User:         user,
			Args:         defaultInitArgs,
			Cwd:          cfg.WorkingDir,
			Capabilities: cfg.Capabilities,
		},
		// enable basic namespaces for gVisor.
		Linux: &specs.Linux{
			Namespaces: namespaces,
		},
		Hostname: cfg.Hostname,
	}

	if cfg.SkipBaseEnv {
		spec.Process.Env = cfg.Env
	} else {
		spec.Process.Env = append(append([]string{}, baseEnv...), cfg.Env...)
	}

	switch {
	case cfg.UIDMappings != nil || cfg.GIDMappings != nil:
		spec.Linux.UIDMappings = cfg.UIDMappings
		spec.Linux.GIDMappings = cfg.GIDMappings
	case os.Geteuid() != 0 && !cfg.SkipDefaultNamespaces:
		spec.Linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Geteuid()), Size: 1},
		}
		spec.Linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getegid()), Size: 1},
		}
	}

	if !cfg.SkipDefaultMounts {
		// Mandatory Linux API Filesystems
		spec.Mounts = append(spec.Mounts,
			specs.Mount{Destination: "/proc", Type: "proc", Source: "proc"},
			specs.Mount{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		)
	}

	// Map host binaries & libraries as readonly. The binaries will be
	// executed in gVisor sandbox, not on the host.
	if !cfg.SkipHostBinaryMounts {
		for _, p := range hostBinaryDirs {
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
	}

	// Add custom mounts. Custom mounts overriding default host mounts create duplicate OCI
	// entries. The later entry overrides the earlier one, as expected by OCI specs.
	for _, m := range cfg.Mounts {
		om, err := m.ociMount()
		if err != nil {
			return nil, err
		}
		spec.Mounts = append(spec.Mounts, om)
	}

	return spec, nil
}

// newBundle creates an OCI bundle on the fly with the given configuration and
// returns its directory.
func newBundle(cfg bundleConfig) (string, error) {
	spec, err := newSpec(cfg)
	if err != nil {
		return "", err
	}

	// Create a bundle directory for the sandbox, along with the empty root
	// filesystem newSpec points at when the caller supplied none.
	bundleDir := filepath.Join(cfg.RuntimeDir, cfg.ID)
	createDir := bundleDir
	if cfg.RootPath == "" {
		createDir = filepath.Join(bundleDir, defaultRootfsDir)
	}
	if err := os.MkdirAll(createDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create bundle directories: %w", err)
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
