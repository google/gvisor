// Copyright 2018 Google Inc.
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

// Package specutils contains utility functions for working with OCI runtime
// specs.
package specutils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
)

// ExePath must point to runsc binary, which is normally the same binary. It's
// changed in tests that aren't linked in the same binary.
var ExePath = "/proc/self/exe"

// LogSpec logs the spec in a human-friendly way.
func LogSpec(spec *specs.Spec) {
	log.Debugf("Spec: %+v", spec)
	log.Debugf("Spec.Hooks: %+v", spec.Hooks)
	log.Debugf("Spec.Linux: %+v", spec.Linux)
	log.Debugf("Spec.Process: %+v", spec.Process)
	log.Debugf("Spec.Root: %+v", spec.Root)
}

// ValidateSpec validates that the spec is compatible with runsc.
func ValidateSpec(spec *specs.Spec) error {
	// Mandatory fields.
	if spec.Process == nil {
		return fmt.Errorf("Spec.Process must be defined: %+v", spec)
	}
	if len(spec.Process.Args) == 0 {
		return fmt.Errorf("Spec.Process.Arg must be defined: %+v", spec.Process)
	}
	if spec.Root == nil {
		return fmt.Errorf("Spec.Root must be defined: %+v", spec)
	}
	if len(spec.Root.Path) == 0 {
		return fmt.Errorf("Spec.Root.Path must be defined: %+v", spec.Root)
	}

	// Unsupported fields.
	if spec.Solaris != nil {
		return fmt.Errorf("Spec.Solaris is not supported: %+v", spec)
	}
	if spec.Windows != nil {
		return fmt.Errorf("Spec.Windows is not supported: %+v", spec)
	}
	if len(spec.Process.SelinuxLabel) != 0 {
		return fmt.Errorf("SELinux is not supported: %s", spec.Process.SelinuxLabel)
	}

	// Docker uses AppArmor by default, so just log that it's being ignored.
	if spec.Process.ApparmorProfile != "" {
		log.Warningf("AppArmor profile %q is being ignored", spec.Process.ApparmorProfile)
	}

	// TODO: Apply seccomp to application inside sandbox.
	if spec.Linux != nil && spec.Linux.Seccomp != nil {
		log.Warningf("Seccomp spec is being ignored")
	}

	for i, m := range spec.Mounts {
		if !path.IsAbs(m.Destination) {
			return fmt.Errorf("Spec.Mounts[%d] Mount.Destination must be an absolute path: %v", i, m)
		}
	}

	// Two annotations are use by containerd to support multi-container pods.
	//   "io.kubernetes.cri.container-type"
	//   "io.kubernetes.cri.sandbox-id"
	containerType, hasContainerType := spec.Annotations[ContainerdContainerTypeAnnotation]
	_, hasSandboxID := spec.Annotations[ContainerdSandboxIDAnnotation]
	switch {
	// Non-containerd use won't set a container type.
	case !hasContainerType:
	case containerType == ContainerdContainerTypeSandbox:
	// When starting a container in an existing sandbox, the sandbox ID
	// must be set.
	case containerType == ContainerdContainerTypeContainer:
		if !hasSandboxID {
			return fmt.Errorf("spec has container-type of %s, but no sandbox ID set", containerType)
		}
	default:
		return fmt.Errorf("unknown container-type: %s", containerType)
	}

	return nil
}

// absPath turns the given path into an absolute path (if it is not already
// absolute) by prepending the base path.
func absPath(base, rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(base, rel)
}

// ReadSpec reads an OCI runtime spec from the given bundle directory.
// ReadSpec also normalizes all potential relative paths into absolute
// path, e.g. spec.Root.Path, mount.Source.
func ReadSpec(bundleDir string) (*specs.Spec, error) {
	// The spec file must be in "config.json" inside the bundle directory.
	specFile := filepath.Join(bundleDir, "config.json")
	specBytes, err := ioutil.ReadFile(specFile)
	if err != nil {
		return nil, fmt.Errorf("error reading spec from file %q: %v", specFile, err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		return nil, fmt.Errorf("error unmarshaling spec from file %q: %v\n %s", specFile, err, string(specBytes))
	}
	if err := ValidateSpec(&spec); err != nil {
		return nil, err
	}
	// Turn any relative paths in the spec to absolute by prepending the bundleDir.
	spec.Root.Path = absPath(bundleDir, spec.Root.Path)
	for i := range spec.Mounts {
		m := &spec.Mounts[i]
		if m.Source != "" {
			m.Source = absPath(bundleDir, m.Source)
		}
	}
	return &spec, nil
}

// GetExecutablePath returns the absolute path to the executable, relative to
// the root. It searches the environment PATH for the first file that exists
// with the given name.
// TODO: Remove this in favor of finding executables via
// boot.GetExecutablePathInternal.
func GetExecutablePath(exec, root string, env []string) (string, error) {
	exec = filepath.Clean(exec)

	// Don't search PATH if exec is a path to a file (absolute or relative).
	if strings.IndexByte(exec, '/') >= 0 {
		return exec, nil
	}

	// Search the PATH for a file whose name matches the one we are looking
	// for.
	path := GetPath(env)
	for _, p := range path {
		abs := filepath.Join(root, p, exec)
		// Do not follow symlink link because the target is in the container
		// root filesystem.
		if _, err := os.Lstat(abs); err == nil {
			// We found it!  Return the path relative to the root.
			return filepath.Join("/", p, exec), nil
		}
	}

	// Could not find a suitable path, just return the original string.
	log.Warningf("could not find executable %s in path %s", exec, path)
	return exec, nil
}

// GetPath returns the PATH as a slice of strings given the environemnt
// variables.
func GetPath(env []string) []string {
	const prefix = "PATH="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.Split(strings.TrimPrefix(e, prefix), ":")
		}
	}
	return nil
}

// Capabilities takes in spec and returns a TaskCapabilities corresponding to
// the spec.
func Capabilities(specCaps *specs.LinuxCapabilities) (*auth.TaskCapabilities, error) {
	var caps auth.TaskCapabilities
	if specCaps != nil {
		var err error
		if caps.BoundingCaps, err = capsFromNames(specCaps.Bounding); err != nil {
			return nil, err
		}
		if caps.EffectiveCaps, err = capsFromNames(specCaps.Effective); err != nil {
			return nil, err
		}
		if caps.InheritableCaps, err = capsFromNames(specCaps.Inheritable); err != nil {
			return nil, err
		}
		if caps.PermittedCaps, err = capsFromNames(specCaps.Permitted); err != nil {
			return nil, err
		}
		// TODO: Support ambient capabilities.
	}
	return &caps, nil
}

var capFromName = map[string]linux.Capability{
	"CAP_CHOWN":            linux.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":     linux.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":  linux.CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":           linux.CAP_FOWNER,
	"CAP_FSETID":           linux.CAP_FSETID,
	"CAP_KILL":             linux.CAP_KILL,
	"CAP_SETGID":           linux.CAP_SETGID,
	"CAP_SETUID":           linux.CAP_SETUID,
	"CAP_SETPCAP":          linux.CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":  linux.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE": linux.CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":    linux.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":        linux.CAP_NET_ADMIN,
	"CAP_NET_RAW":          linux.CAP_NET_RAW,
	"CAP_IPC_LOCK":         linux.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":        linux.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":       linux.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":        linux.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":       linux.CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":       linux.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":        linux.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":        linux.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":         linux.CAP_SYS_BOOT,
	"CAP_SYS_NICE":         linux.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":     linux.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":         linux.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":   linux.CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":            linux.CAP_MKNOD,
	"CAP_LEASE":            linux.CAP_LEASE,
	"CAP_AUDIT_WRITE":      linux.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":    linux.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":          linux.CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":     linux.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":        linux.CAP_MAC_ADMIN,
	"CAP_SYSLOG":           linux.CAP_SYSLOG,
	"CAP_WAKE_ALARM":       linux.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":    linux.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":       linux.CAP_AUDIT_READ,
}

func capsFromNames(names []string) (auth.CapabilitySet, error) {
	var caps []linux.Capability
	for _, n := range names {
		c, ok := capFromName[n]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		caps = append(caps, c)
	}
	return auth.CapabilitySetOfMany(caps), nil
}

// Is9PMount returns true if the given mount can be mounted as an external gofer.
func Is9PMount(m specs.Mount) bool {
	return m.Type == "bind" && m.Source != "" && IsSupportedDevMount(m)
}

// IsSupportedDevMount returns true if the mount is a supported /dev mount.
// Only mount that does not conflict with runsc default /dev mount is
// supported.
func IsSupportedDevMount(m specs.Mount) bool {
	// These are devices exist inside sentry. See pkg/sentry/fs/dev/dev.go
	var existingDevices = []string{
		"/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr",
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random",
		"/dev/urandom", "/dev/shm", "/dev/pts", "/dev/ptmx",
	}
	dst := filepath.Clean(m.Destination)
	if dst == "/dev" {
		// OCI spec uses many different mounts for the things inside of '/dev'. We
		// have a single mount at '/dev' that is always mounted, regardless of
		// whether it was asked for, as the spec says we SHOULD.
		return false
	}
	for _, dev := range existingDevices {
		if dst == dev || strings.HasPrefix(dst, dev+"/") {
			return false
		}
	}
	return true
}

// BinPath returns the real path to self, resolving symbolink links. This is done
// to make the process name appears as 'runsc', instead of 'exe'.
func BinPath() (string, error) {
	binPath, err := filepath.EvalSymlinks(ExePath)
	if err != nil {
		return "", fmt.Errorf(`error resolving %q symlink: %v`, ExePath, err)
	}
	return binPath, nil
}

const (
	// ContainerdContainerTypeAnnotation is the OCI annotation set by
	// containerd to indicate whether the container to create should have
	// its own sandbox or a container within an existing sandbox.
	ContainerdContainerTypeAnnotation = "io.kubernetes.cri.container-type"
	// ContainerdContainerTypeContainer is the container type value
	// indicating the container should be created in an existing sandbox.
	ContainerdContainerTypeContainer = "container"
	// ContainerdContainerTypeSandbox is the container type value
	// indicating the container should be created in a new sandbox.
	ContainerdContainerTypeSandbox = "sandbox"

	// ContainerdSandboxIDAnnotation is the OCI annotation set to indicate
	// which sandbox the container should be created in when the container
	// is not the first container in the sandbox.
	ContainerdSandboxIDAnnotation = "io.kubernetes.cri.sandbox-id"
)

// ShouldCreateSandbox returns true if the spec indicates that a new sandbox
// should be created for the container. If false, the container should be
// started in an existing sandbox.
func ShouldCreateSandbox(spec *specs.Spec) bool {
	t, ok := spec.Annotations[ContainerdContainerTypeAnnotation]
	return !ok || t == ContainerdContainerTypeSandbox
}

// SandboxID returns the ID of the sandbox to join and whether an ID was found
// in the spec.
func SandboxID(spec *specs.Spec) (string, bool) {
	id, ok := spec.Annotations[ContainerdSandboxIDAnnotation]
	return id, ok
}

// WaitForReady waits for a process to become ready. The process is ready when
// the 'ready' function returns true. It continues to wait if 'ready' returns
// false. It returns error on timeout, if the process stops or if 'ready' fails.
func WaitForReady(pid int, timeout time.Duration, ready func() (bool, error)) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Millisecond
	b.MaxInterval = 1 * time.Second
	b.MaxElapsedTime = timeout

	op := func() error {
		if ok, err := ready(); err != nil {
			return backoff.Permanent(err)
		} else if ok {
			return nil
		}

		// Check if the process is still running.
		// If the process is alive, child is 0 because of the NOHANG option.
		// If the process has terminated, child equals the process id.
		var ws syscall.WaitStatus
		var ru syscall.Rusage
		child, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, &ru)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("error waiting for process: %v", err))
		} else if child == pid {
			return backoff.Permanent(fmt.Errorf("process %d has terminated", pid))
		}
		return fmt.Errorf("process %d not running yet", pid)
	}
	return backoff.Retry(op, b)
}
