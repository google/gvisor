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
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/mohae/deepcopy"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// ExePath must point to runsc binary, which is normally the same binary. It's
// changed in tests that aren't linked in the same binary.
var ExePath = "/proc/self/exe"

// Version is the supported spec version.
var Version = specs.Version

// LogSpec logs the spec in a human-friendly way.
func LogSpec(orig *specs.Spec) {
	if !log.IsLogging(log.Debug) {
		return
	}

	// Strip down parts of the spec that are not interesting.
	spec := deepcopy.Copy(orig).(*specs.Spec)
	if spec.Process != nil {
		spec.Process.Capabilities = nil
	}
	if spec.Linux != nil {
		spec.Linux.Seccomp = nil
		spec.Linux.MaskedPaths = nil
		spec.Linux.ReadonlyPaths = nil
		if spec.Linux.Resources != nil {
			spec.Linux.Resources.Devices = nil
		}
	}

	out, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		log.Debugf("Failed to marshal spec: %v", err)
		return
	}
	log.Debugf("Spec:\n%s", out)
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

	// PR_SET_NO_NEW_PRIVS is assumed to always be set.
	// See kernel.Task.updateCredsForExecLocked.
	if !spec.Process.NoNewPrivileges {
		log.Warningf("noNewPrivileges ignored. PR_SET_NO_NEW_PRIVS is assumed to always be set.")
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

	// CRI specifies whether a container should start a new sandbox, or run
	// another container in an existing sandbox.
	switch SpecContainerType(spec) {
	case ContainerTypeContainer:
		// When starting a container in an existing sandbox, the
		// sandbox ID must be set.
		if _, ok := SandboxID(spec); !ok {
			return fmt.Errorf("spec has container-type of container, but no sandbox ID set")
		}
	case ContainerTypeUnknown:
		return fmt.Errorf("unknown container-type")
	default:
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
func ReadSpec(bundleDir string, conf *config.Config) (*specs.Spec, error) {
	specFile, err := OpenSpec(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("error opening spec file %q: %v", filepath.Join(bundleDir, "config.json"), err)
	}
	defer specFile.Close()
	return ReadSpecFromFile(bundleDir, specFile, conf)
}

// ReadSpecFromFile reads an OCI runtime spec from the given File, and
// normalizes all relative paths into absolute by prepending the bundle dir.
func ReadSpecFromFile(bundleDir string, specFile *os.File, conf *config.Config) (*specs.Spec, error) {
	if _, err := specFile.Seek(0, io.SeekStart); err != nil {
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

	// Override flags using annotation to allow customization per sandbox
	// instance.
	for annotation, val := range spec.Annotations {
		const flagPrefix = "dev.gvisor.flag."
		if strings.HasPrefix(annotation, flagPrefix) {
			name := annotation[len(flagPrefix):]
			log.Infof("Overriding flag: %s=%q", name, val)
			if err := conf.Override(flag.CommandLine, name, val); err != nil {
				return nil, err
			}
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
		return nil, fmt.Errorf("error unmarshaling mounts: %v\nJSON bytes:\n%s", err, string(bytes))
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
		// TODO(gvisor.dev/issue/3166): Support ambient capabilities.
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

// IsGoferMount returns true if the given mount can be mounted as an external
// gofer.
func IsGoferMount(m specs.Mount) bool {
	MaybeConvertToBindMount(&m)
	return m.Type == "bind" && m.Source != ""
}

// MaybeConvertToBindMount converts mount type to "bind" in case any of the
// mount options are either "bind" or "rbind" as required by the OCI spec.
//
// "For bind mounts (when options include either bind or rbind), the type is a
// dummy, often "none" (not listed in /proc/filesystems)."
func MaybeConvertToBindMount(m *specs.Mount) {
	if m.Type == "bind" {
		return
	}
	for _, opt := range m.Options {
		if opt == "bind" || opt == "rbind" {
			m.Type = "bind"
			return
		}
	}
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
		var ws unix.WaitStatus
		var ru unix.Rusage
		child, err := unix.Wait4(pid, &ws, unix.WNOHANG, &ru)
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
//     <yyyymmdd-hhmmss.uuuuuu>
//   - %COMMAND%: is replaced with 'command'
//   - %TEST%: is replaced with 'test' (omitted by default)
func DebugLogFile(logPattern, command, test string) (*os.File, error) {
	if strings.HasSuffix(logPattern, "/") {
		// Default format: <debug-log>/runsc.log.<yyyymmdd-hhmmss.uuuuuu>.<command>.txt
		logPattern += "runsc.log.%TIMESTAMP%.%COMMAND%.txt"
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

// IsDebugCommand returns true if the command should be debugged or not, based
// on the current configuration.
func IsDebugCommand(conf *config.Config, command string) bool {
	if len(conf.DebugCommand) == 0 {
		// Debug everything by default.
		return true
	}
	filter := conf.DebugCommand
	rv := true
	if filter[0] == '!' {
		// Negate the match, e.g. !boot should log all, but "boot".
		filter = filter[1:]
		rv = false
	}
	for _, cmd := range strings.Split(filter, ",") {
		if cmd == command {
			return rv
		}
	}
	return !rv
}

// SafeSetupAndMount creates the mount point and calls Mount with the given
// flags. procPath is the path to procfs. If it is "", procfs is assumed to be
// mounted at /proc.
func SafeSetupAndMount(src, dst, typ string, flags uint32, procPath string) error {
	// Create the mount point inside. The type must be the same as the source
	// (file or directory).
	var isDir bool
	if typ == "proc" {
		// Special case, as there is no source directory for proc mounts.
		isDir = true
	} else if fi, err := os.Stat(src); err != nil {
		return fmt.Errorf("stat(%q) failed: %v", src, err)
	} else {
		isDir = fi.IsDir()
	}

	if isDir {
		// Create the destination directory.
		if err := os.MkdirAll(dst, 0777); err != nil {
			return fmt.Errorf("mkdir(%q) failed: %v", dst, err)
		}
	} else {
		// Create the parent destination directory.
		parent := path.Dir(dst)
		if err := os.MkdirAll(parent, 0777); err != nil {
			return fmt.Errorf("mkdir(%q) failed: %v", parent, err)
		}
		// Create the destination file if it does not exist.
		f, err := os.OpenFile(dst, unix.O_CREAT, 0777)
		if err != nil {
			return fmt.Errorf("open(%q) failed: %v", dst, err)
		}
		f.Close()
	}

	// Do the mount.
	if err := SafeMount(src, dst, typ, uintptr(flags), "", procPath); err != nil {
		return fmt.Errorf("mount(%q, %q, %d) failed: %v", src, dst, flags, err)
	}
	return nil
}

// ErrSymlinkMount is returned by SafeMount when the mount destination is found
// to be a symlink.
type ErrSymlinkMount struct {
	error
}

// SafeMount is like unix.Mount, but will fail if dst is a symlink. procPath is
// the path to procfs. If it is "", procfs is assumed to be mounted at /proc.
//
// SafeMount can fail when dst contains a symlink. However, it is called in the
// normal case with a destination consisting of a known root (/proc/root) and
// symlink-free path (from resolveSymlink).
func SafeMount(src, dst, fstype string, flags uintptr, data, procPath string) error {
	// Open the destination.
	fd, err := unix.Open(dst, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to safely mount: Open(%s, _, _): %w", dst, err)
	}
	defer unix.Close(fd)

	// Use /proc/self/fd/ to verify that we opened the intended destination. This
	// guards against dst being a symlink, in which case we could accidentally
	// mount over the symlink's target.
	if procPath == "" {
		procPath = "/proc"
	}
	safePath := filepath.Join(procPath, "self/fd", strconv.Itoa(fd))
	target, err := os.Readlink(safePath)
	if err != nil {
		return fmt.Errorf("failed to safely mount: Readlink(%s): %w", safePath, err)
	}
	if dst != target {
		return &ErrSymlinkMount{fmt.Errorf("failed to safely mount: expected to open %s, but found %s", dst, target)}
	}

	return unix.Mount(src, safePath, fstype, flags, data)
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

// RetryEintr retries the function until an error different than EINTR is
// returned.
func RetryEintr(f func() (uintptr, uintptr, error)) (uintptr, uintptr, error) {
	for {
		r1, r2, err := f()
		if err != unix.EINTR {
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

// ResolveEnvs transforms lists of environment variables into a single list of
// environment variables. If a variable is defined multiple times, the last
// value is used.
func ResolveEnvs(envs ...[]string) ([]string, error) {
	// First create a map of variable names to values. This removes any
	// duplicates.
	envMap := make(map[string]string)
	for _, env := range envs {
		for _, str := range env {
			parts := strings.SplitN(str, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid variable: %s", str)
			}
			envMap[parts[0]] = parts[1]
		}
	}
	// Reassemble envMap into a list of environment variables of the form
	// NAME=VALUE.
	env := make([]string, 0, len(envMap))
	for k, v := range envMap {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env, nil
}

// FaqErrorMsg returns an error message pointing to the FAQ.
func FaqErrorMsg(anchor, msg string) string {
	return fmt.Sprintf("%s; see https://gvisor.dev/faq#%s for more details", msg, anchor)
}
