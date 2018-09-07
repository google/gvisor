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

package boot

import (
	"fmt"
	"strconv"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/sentry/watchdog"
)

// PlatformType tells which platform to use.
type PlatformType int

const (
	// PlatformPtrace runs the sandbox with the ptrace platform.
	PlatformPtrace PlatformType = iota

	// PlatformKVM runs the sandbox with the KVM platform.
	PlatformKVM
)

// MakePlatformType converts type from string.
func MakePlatformType(s string) (PlatformType, error) {
	switch s {
	case "ptrace":
		return PlatformPtrace, nil
	case "kvm":
		return PlatformKVM, nil
	default:
		return 0, fmt.Errorf("invalid platform type %q", s)
	}
}

func (p PlatformType) String() string {
	switch p {
	case PlatformPtrace:
		return "ptrace"
	case PlatformKVM:
		return "kvm"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

// FileAccessType tells how the filesystem is accessed.
type FileAccessType int

const (
	// FileAccessShared sends IO requests to a Gofer process that validates the
	// requests and forwards them to the host.
	FileAccessShared FileAccessType = iota

	// FileAccessExclusive is the same as FileAccessShared, but enables
	// extra caching for improved performance. It should only be used if
	// the sandbox has exclusive access to the filesystem.
	FileAccessExclusive
)

// MakeFileAccessType converts type from string.
func MakeFileAccessType(s string) (FileAccessType, error) {
	switch s {
	case "shared":
		return FileAccessShared, nil
	case "exclusive":
		return FileAccessExclusive, nil
	default:
		return 0, fmt.Errorf("invalid file access type %q", s)
	}
}

func (f FileAccessType) String() string {
	switch f {
	case FileAccessShared:
		return "shared"
	case FileAccessExclusive:
		return "exclusive"
	default:
		return fmt.Sprintf("unknown(%d)", f)
	}
}

// NetworkType tells which network stack to use.
type NetworkType int

const (
	// NetworkSandbox uses internal network stack, isolated from the host.
	NetworkSandbox NetworkType = iota

	// NetworkHost redirects network related syscalls to the host network.
	NetworkHost

	// NetworkNone sets up just loopback using netstack.
	NetworkNone
)

// MakeNetworkType converts type from string.
func MakeNetworkType(s string) (NetworkType, error) {
	switch s {
	case "sandbox":
		return NetworkSandbox, nil
	case "host":
		return NetworkHost, nil
	case "none":
		return NetworkNone, nil
	default:
		return 0, fmt.Errorf("invalid network type %q", s)
	}
}

func (n NetworkType) String() string {
	switch n {
	case NetworkSandbox:
		return "sandbox"
	case NetworkHost:
		return "host"
	case NetworkNone:
		return "none"
	default:
		return fmt.Sprintf("unknown(%d)", n)
	}
}

// MakeWatchdogAction converts type from string.
func MakeWatchdogAction(s string) (watchdog.Action, error) {
	switch strings.ToLower(s) {
	case "log", "logwarning":
		return watchdog.LogWarning, nil
	case "panic":
		return watchdog.Panic, nil
	default:
		return 0, fmt.Errorf("invalid watchdog action %q", s)
	}
}

// Config holds configuration that is not part of the runtime spec.
type Config struct {
	// RootDir is the runtime root directory.
	RootDir string

	// Debug indicates that debug logging should be enabled.
	Debug bool

	// LogFilename is the filename to log to, if not empty.
	LogFilename string

	// LogFormat is the log format, "text" or "json".
	LogFormat string

	// DebugLogDir is the directory to log debug information to, if not
	// empty.
	DebugLogDir string

	// FileAccess indicates how the filesystem is accessed.
	FileAccess FileAccessType

	// Overlay is whether to wrap the root filesystem in an overlay.
	Overlay bool

	// Network indicates what type of network to use.
	Network NetworkType

	// LogPackets indicates that all network packets should be logged.
	LogPackets bool

	// Platform is the platform to run on.
	Platform PlatformType

	// Strace indicates that strace should be enabled.
	Strace bool

	// StraceSyscalls is the set of syscalls to trace.  If StraceEnable is
	// true and this list is empty, then all syscalls will be traced.
	StraceSyscalls []string

	// StraceLogSize is the max size of data blobs to display.
	StraceLogSize uint

	// DisableSeccomp indicates whether seccomp syscall filters should be
	// disabled. Pardon the double negation, but default to enabled is important.
	DisableSeccomp bool

	// MultiContainer enables multiple containers support inside one sandbox.
	// TODO: Remove this when multiple container is fully supported.
	MultiContainer bool

	// SpecFile is the file containing the OCI spec.
	SpecFile string

	// WatchdogAction sets what action the watchdog takes when triggered.
	WatchdogAction watchdog.Action

	// PanicSignal register signal handling that panics. Usually set to
	// SIGUSR2(12) to troubleshoot hangs. -1 disables it.
	PanicSignal int

	// TestOnlyAllowRunAsCurrentUserWithoutChroot should only be used in
	// tests. It allows runsc to start the sandbox process as the current
	// user, and without chrooting the sandbox process. This can be
	// necessary in test environments that have limited capabilities.
	TestOnlyAllowRunAsCurrentUserWithoutChroot bool
}

// ToFlags returns a slice of flags that correspond to the given Config.
func (c *Config) ToFlags() []string {
	return []string{
		"--root=" + c.RootDir,
		"--debug=" + strconv.FormatBool(c.Debug),
		"--log=" + c.LogFilename,
		"--log-format=" + c.LogFormat,
		"--debug-log-dir=" + c.DebugLogDir,
		"--file-access=" + c.FileAccess.String(),
		"--overlay=" + strconv.FormatBool(c.Overlay),
		"--multi-container=" + strconv.FormatBool(c.MultiContainer),
		"--network=" + c.Network.String(),
		"--log-packets=" + strconv.FormatBool(c.LogPackets),
		"--platform=" + c.Platform.String(),
		"--strace=" + strconv.FormatBool(c.Strace),
		"--strace-syscalls=" + strings.Join(c.StraceSyscalls, ","),
		"--strace-log-size=" + strconv.Itoa(int(c.StraceLogSize)),
		"--watchdog-action=" + c.WatchdogAction.String(),
		"--panic-signal=" + strconv.Itoa(c.PanicSignal),
	}
}
