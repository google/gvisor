// Copyright 2018 The gVisor Authors.
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// ExePath must point to runsc binary, which is normally the same binary. It's
// changed in tests that aren't linked in the same binary.
var ExePath = "/proc/self/exe"

// Version is the supported spec version.
var Version = specs.Version

// LogSpec logs the spec in a human-friendly way.
func LogSpec(spec *specs.Spec) {
	log.Debugf("Spec: %+v", spec)
	log.Debugf("Spec.Hooks: %+v", spec.Hooks)
	log.Debugf("Spec.Linux: %+v", spec.Linux)
	if spec.Linux != nil && spec.Linux.Resources != nil {
		res := spec.Linux.Resources
		log.Debugf("Spec.Linux.Resources.Memory: %+v", res.Memory)
		log.Debugf("Spec.Linux.Resources.CPU: %+v", res.CPU)
		log.Debugf("Spec.Linux.Resources.BlockIO: %+v", res.BlockIO)
		log.Debugf("Spec.Linux.Resources.Network: %+v", res.Network)
	}
	log.Debugf("Spec.Process: %+v", spec.Process)
	log.Debugf("Spec.Root: %+v", spec.Root)
	log.Debugf("Spec.Mounts: %+v", spec.Mounts)
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

	// TODO(gvisor.dev/issue/510): Apply seccomp to application inside sandbox.
	if spec.Linux != nil && spec.Linux.Seccomp != nil {
		log.Warningf("Seccomp spec is being ignored")
	}

	if spec.Linux != nil && spec.Linux.RootfsPropagation != "" {
		if err := validateRootfsPropagation(spec.Linux.RootfsPropagation); err != nil {
			return err
		}
	}
	for _, m := range spec.Mounts {
		if err := validateMount(&m); err != nil {
			return err
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

// OpenSpec opens an OCI runtime spec from the given bundle directory.
func OpenSpec(bundleDir string) (*os.File, error) {
	// The spec file must be named "config.json" inside the bundle directory.
	return os.Open(filepath.Join(bundleDir, "config.json"))
}

// ReadSpec reads an OCI runtime spec from the given bundle directory.
// ReadSpec also normalizes all potential relative paths into absolute
// path, e.g. spec.Root.Path, mount.Source.
func ReadSpec(bundleDir string) (*specs.Spec, error) {
	specFile, err := OpenSpec(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("error opening spec file %q: %v", filepath.Join(bundleDir, "config.json"), err)
	}
	defer specFile.Close()
	return ReadSpecFromFile(bundleDir, specFile)
}

// ReadSpecFromFile reads an OCI runtime spec from the given File, and
// normalizes all relative paths into absolute by prepending the bundle dir.
func ReadSpecFromFile(bundleDir string, specFile *os.File) (*specs.Spec, error) {
	if _, err := specFile.Seek(0, os.SEEK_SET); err != nil {
		return nil, fmt.Errorf("error seeking to beginning of file %q: %v", specFile.Name(), err)
	}
	specBytes, err := ioutil.ReadAll(specFile)
	if err != nil {
		return nil, fmt.Errorf("error reading spec from file %q: %v", specFile.Name(), err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(specBytes, &spec); err != nil {
		return nil, fmt.Errorf("error unmarshaling spec from file %q: %v\n %s", specFile.Name(), err, string(specBytes))
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

// ReadMounts reads mount list from a file.
func ReadMounts(f *os.File) ([]specs.Mount, error) {
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading mounts: %v", err)
	}
	var mounts []specs.Mount
	if err := json.Unmarshal(bytes, &mounts); err != nil {
		return nil, fmt.Errorf("error unmarshaling mounts: %v\n %s", err, string(bytes))
	}
	return mounts, nil
}

// Capabilities takes in spec and returns a TaskCapabilities corresponding to
// the spec.
func Capabilities(enableRaw bool, specCaps *specs.LinuxCapabilities) (*auth.TaskCapabilities, error) {
	// Strip CAP_NET_RAW from all capability sets if necessary.
	skipSet := map[linux.Capability]struct{}{}
	if !enableRaw {
		skipSet[linux.CAP_NET_RAW] = struct{}{}
	}

	var caps auth.TaskCapabilities
	if specCaps != nil {
		var err error
		if caps.BoundingCaps, err = capsFromNames(specCaps.Bounding, skipSet); err != nil {
			return nil, err
		}
		if caps.EffectiveCaps, err = capsFromNames(specCaps.Effective, skipSet); err != nil {
			return nil, err
		}
		if caps.InheritableCaps, err = capsFromNames(specCaps.Inheritable, skipSet); err != nil {
			return nil, err
		}
		if caps.PermittedCaps, err = capsFromNames(specCaps.Permitted, skipSet); err != nil {
			return nil, err
		}
		// TODO(nlacasse): Support ambient capabilities.
	}
	return &caps, nil
}

// AllCapabilities returns a LinuxCapabilities struct with all capabilities.
func AllCapabilities() *specs.LinuxCapabilities {
	var names []string
	for n := range capFromName {
		names = append(names, n)
	}
	return &specs.LinuxCapabilities{
		Bounding:    names,
		Effective:   names,
		Inheritable: names,
		Permitted:   names,
		Ambient:     names,
	}
}

// AllCapabilitiesUint64 returns a bitmask containing all capabilities set.
func AllCapabilitiesUint64() uint64 {
	var rv uint64
	for _, cap := range capFromName {
		rv |= bits.MaskOf64(int(cap))
	}
	return rv
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

func capsFromNames(names []string, skipSet map[linux.Capability]struct{}) (auth.CapabilitySet, error) {
	var caps []linux.Capability
	for _, n := range names {
		c, ok := capFromName[n]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		// Should we skip this capabilty?
		if _, ok := skipSet[c]; ok {
			continue
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

// DebugLogFile opens a log file using 'logPattern' as location. If 'logPattern'
// ends with '/', it's used as a directory with default file name.
// 'logPattern' can contain variables that are substituted:
//   - %TIMESTAMP%: is replaced with a timestamp using the following format:
//			<yyyymmdd-hhmmss.uuuuuu>
//	 - %COMMAND%: is replaced with 'command'
//	 - %TEST%: is replaced with 'test' (omitted by default)
func DebugLogFile(logPattern, command, test string) (*os.File, error) {
	if strings.HasSuffix(logPattern, "/") {
		// Default format: <debug-log>/runsc.log.<yyyymmdd-hhmmss.uuuuuu>.<command>
		logPattern += "runsc.log.%TIMESTAMP%.%COMMAND%"
	}
	logPattern = strings.Replace(logPattern, "%TIMESTAMP%", time.Now().Format("20060102-150405.000000"), -1)
	logPattern = strings.Replace(logPattern, "%COMMAND%", command, -1)
	logPattern = strings.Replace(logPattern, "%TEST%", test, -1)

	dir := filepath.Dir(logPattern)
	if err := os.MkdirAll(dir, 0775); err != nil {
		return nil, fmt.Errorf("error creating dir %q: %v", dir, err)
	}
	return os.OpenFile(logPattern, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
}

// Mount creates the mount point and calls Mount with the given flags.
func Mount(src, dst, typ string, flags uint32) error {
	// Create the mount point inside. The type must be the same as the
	// source (file or directory).
	var isDir bool
	if typ == "proc" {
		// Special case, as there is no source directory for proc mounts.
		isDir = true
	} else if fi, err := os.Stat(src); err != nil {
		return fmt.Errorf("Stat(%q) failed: %v", src, err)
	} else {
		isDir = fi.IsDir()
	}

	if isDir {
		// Create the destination directory.
		if err := os.MkdirAll(dst, 0777); err != nil {
			return fmt.Errorf("Mkdir(%q) failed: %v", dst, err)
		}
	} else {
		// Create the parent destination directory.
		parent := path.Dir(dst)
		if err := os.MkdirAll(parent, 0777); err != nil {
			return fmt.Errorf("Mkdir(%q) failed: %v", parent, err)
		}
		// Create the destination file if it does not exist.
		f, err := os.OpenFile(dst, syscall.O_CREAT, 0777)
		if err != nil {
			return fmt.Errorf("Open(%q) failed: %v", dst, err)
		}
		f.Close()
	}

	// Do the mount.
	if err := syscall.Mount(src, dst, typ, uintptr(flags), ""); err != nil {
		return fmt.Errorf("Mount(%q, %q, %d) failed: %v", src, dst, flags, err)
	}
	return nil
}

// ContainsStr returns true if 'str' is inside 'strs'.
func ContainsStr(strs []string, str string) bool {
	for _, s := range strs {
		if s == str {
			return true
		}
	}
	return false
}

// Cleanup allows defers to be aborted when cleanup needs to happen
// conditionally. Usage:
// c := MakeCleanup(func() { f.Close() })
// defer c.Clean() // any failure before release is called will close the file.
// ...
// c.Release() // on success, aborts closing the file and return it.
// return f
type Cleanup struct {
	clean func()
}

// MakeCleanup creates a new Cleanup object.
func MakeCleanup(f func()) Cleanup {
	return Cleanup{clean: f}
}

// Clean calls the cleanup function.
func (c *Cleanup) Clean() {
	if c.clean != nil {
		c.clean()
		c.clean = nil
	}
}

// Release releases the cleanup from its duties, i.e. cleanup function is not
// called after this point.
func (c *Cleanup) Release() {
	c.clean = nil
}

// RetryEintr retries the function until an error different than EINTR is
// returned.
func RetryEintr(f func() (uintptr, uintptr, error)) (uintptr, uintptr, error) {
	for {
		r1, r2, err := f()
		if err != syscall.EINTR {
			return r1, r2, err
		}
	}
}

// GetOOMScoreAdj reads the given process' oom_score_adj
func GetOOMScoreAdj(pid int) (int, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// GetParentPid gets the parent process ID of the specified PID.
func GetParentPid(pid int) (int, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	var cpid string
	var name string
	var state string
	var ppid int
	// Parse after the binary name.
	_, err = fmt.Sscanf(string(data),
		"%v %v %v %d",
		// cpid is ignored.
		&cpid,
		// name is ignored.
		&name,
		// state is ignored.
		&state,
		&ppid)

	if err != nil {
		return 0, err
	}

	return ppid, nil
}

// EnvVar looks for a varible value in the env slice assuming the following
// format: "NAME=VALUE".
func EnvVar(env []string, name string) (string, bool) {
	prefix := name + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return strings.TrimPrefix(e, prefix), true
		}
	}
	return "", false
}
