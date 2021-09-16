// Copyright 2020 The gVisor Authors.
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

// Package config provides basic infrastructure to set configuration settings
// for runsc. The configuration is set by flags to the command line. They can
// also propagate to a different process using the same flags.
package config

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/refs"
	controlpb "gvisor.dev/gvisor/pkg/sentry/control/control_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
)

// Config holds configuration that is not part of the runtime spec.
//
// Follow these steps to add a new flag:
//   1. Create a new field in Config.
//   2. Add a field tag with the flag name
//   3. Register a new flag in flags.go, with name and description
//   4. Add any necessary validation into validate()
//   5. If adding an enum, follow the same pattern as FileAccessType
//
type Config struct {
	// RootDir is the runtime root directory.
	RootDir string `flag:"root"`

	// Traceback changes the Go runtime's traceback level.
	Traceback string `flag:"traceback"`

	// Debug indicates that debug logging should be enabled.
	Debug bool `flag:"debug"`

	// LogFilename is the filename to log to, if not empty.
	LogFilename string `flag:"log"`

	// LogFormat is the log format.
	LogFormat string `flag:"log-format"`

	// DebugLog is the path to log debug information to, if not empty.
	DebugLog string `flag:"debug-log"`

	// PanicLog is the path to log GO's runtime messages, if not empty.
	PanicLog string `flag:"panic-log"`

	// CoverageReport is the path to write Go coverage information, if not empty.
	CoverageReport string `flag:"coverage-report"`

	// DebugLogFormat is the log format for debug.
	DebugLogFormat string `flag:"debug-log-format"`

	// FileAccess indicates how the root filesystem is accessed.
	FileAccess FileAccessType `flag:"file-access"`

	// FileAccessMounts indicates how non-root volumes are accessed.
	FileAccessMounts FileAccessType `flag:"file-access-mounts"`

	// Overlay is whether to wrap the root filesystem in an overlay.
	Overlay bool `flag:"overlay"`

	// Verity is whether there's one or more verity file system to mount.
	Verity bool `flag:"verity"`

	// FSGoferHostUDS enables the gofer to mount a host UDS.
	FSGoferHostUDS bool `flag:"fsgofer-host-uds"`

	// Network indicates what type of network to use.
	Network NetworkType `flag:"network"`

	// EnableRaw indicates whether raw sockets should be enabled. Raw
	// sockets are disabled by stripping CAP_NET_RAW from the list of
	// capabilities.
	EnableRaw bool `flag:"net-raw"`

	// AllowPacketEndpointWrite enables write operations on packet endpoints.
	AllowPacketEndpointWrite bool `flag:"TESTONLY-allow-packet-endpoint-write"`

	// HardwareGSO indicates that hardware segmentation offload is enabled.
	HardwareGSO bool `flag:"gso"`

	// SoftwareGSO indicates that software segmentation offload is enabled.
	SoftwareGSO bool `flag:"software-gso"`

	// TXChecksumOffload indicates that TX Checksum Offload is enabled.
	TXChecksumOffload bool `flag:"tx-checksum-offload"`

	// RXChecksumOffload indicates that RX Checksum Offload is enabled.
	RXChecksumOffload bool `flag:"rx-checksum-offload"`

	// QDisc indicates the type of queuening discipline to use by default
	// for non-loopback interfaces.
	QDisc QueueingDiscipline `flag:"qdisc"`

	// LogPackets indicates that all network packets should be logged.
	LogPackets bool `flag:"log-packets"`

	// Platform is the platform to run on.
	Platform string `flag:"platform"`

	// Strace indicates that strace should be enabled.
	Strace bool `flag:"strace"`

	// StraceSyscalls is the set of syscalls to trace (comma-separated values).
	// If StraceEnable is true and this string is empty, then all syscalls will
	// be traced.
	StraceSyscalls string `flag:"strace-syscalls"`

	// StraceLogSize is the max size of data blobs to display.
	StraceLogSize uint `flag:"strace-log-size"`

	// StraceEvent indicates sending strace to events if true. Strace is
	// sent to log if false.
	StraceEvent bool `flag:"strace-event"`

	// DisableSeccomp indicates whether seccomp syscall filters should be
	// disabled. Pardon the double negation, but default to enabled is important.
	DisableSeccomp bool

	// WatchdogAction sets what action the watchdog takes when triggered.
	WatchdogAction watchdog.Action `flag:"watchdog-action"`

	// PanicSignal registers signal handling that panics. Usually set to
	// SIGUSR2(12) to troubleshoot hangs. -1 disables it.
	PanicSignal int `flag:"panic-signal"`

	// ProfileEnable is set to prepare the sandbox to be profiled.
	ProfileEnable bool `flag:"profile"`

	// ProfileBlock collects a block profile to the passed file for the
	// duration of the container execution. Requires ProfileEnabled.
	ProfileBlock string `flag:"profile-block"`

	// ProfileCPU collects a CPU profile to the passed file for the
	// duration of the container execution. Requires ProfileEnabled.
	ProfileCPU string `flag:"profile-cpu"`

	// ProfileHeap collects a heap profile to the passed file for the
	// duration of the container execution. Requires ProfileEnabled.
	ProfileHeap string `flag:"profile-heap"`

	// ProfileMutex collects a mutex profile to the passed file for the
	// duration of the container execution. Requires ProfileEnabled.
	ProfileMutex string `flag:"profile-mutex"`

	// TraceFile collects a Go runtime execution trace to the passed file
	// for the duration of the container execution.
	TraceFile string `flag:"trace"`

	// Controls defines the controls that may be enabled.
	Controls controlConfig `flag:"controls"`

	// RestoreFile is the path to the saved container image
	RestoreFile string

	// NumNetworkChannels controls the number of AF_PACKET sockets that map
	// to the same underlying network device. This allows netstack to better
	// scale for high throughput use cases.
	NumNetworkChannels int `flag:"num-network-channels"`

	// Rootless allows the sandbox to be started with a user that is not root.
	// Defense in depth measures are weaker in rootless mode. Specifically, the
	// sandbox and Gofer process run as root inside a user namespace with root
	// mapped to the caller's user. When using rootless, the container root path
	// should not have a symlink.
	Rootless bool `flag:"rootless"`

	// AlsoLogToStderr allows to send log messages to stderr.
	AlsoLogToStderr bool `flag:"alsologtostderr"`

	// ReferenceLeakMode sets reference leak check mode
	ReferenceLeak refs.LeakMode `flag:"ref-leak-mode"`

	// CPUNumFromQuota sets CPU number count to available CPU quota, using
	// least integer value greater than or equal to quota.
	//
	// E.g. 0.2 CPU quota will result in 1, and 1.9 in 2.
	CPUNumFromQuota bool `flag:"cpu-num-from-quota"`

	// Enables VFS2.
	VFS2 bool `flag:"vfs2"`

	// Enables FUSE usage.
	FUSE bool `flag:"fuse"`

	// Allows overriding of flags in OCI annotations.
	AllowFlagOverride bool `flag:"allow-flag-override"`

	// Enables seccomp inside the sandbox.
	OCISeccomp bool `flag:"oci-seccomp"`

	// Mounts the cgroup filesystem backed by the sentry's cgroupfs.
	Cgroupfs bool `flag:"cgroupfs"`

	// TestOnlyAllowRunAsCurrentUserWithoutChroot should only be used in
	// tests. It allows runsc to start the sandbox process as the current
	// user, and without chrooting the sandbox process. This can be
	// necessary in test environments that have limited capabilities. When
	// disabling chroot, the container root path should not have a symlink.
	TestOnlyAllowRunAsCurrentUserWithoutChroot bool `flag:"TESTONLY-unsafe-nonroot"`

	// TestOnlyTestNameEnv should only be used in tests. It looks up for the
	// test name in the container environment variables and adds it to the debug
	// log file name. This is done to help identify the log with the test when
	// multiple tests are run in parallel, since there is no way to pass
	// parameters to the runtime from docker.
	TestOnlyTestNameEnv string `flag:"TESTONLY-test-name-env"`
}

func (c *Config) validate() error {
	if c.FileAccess == FileAccessShared && c.Overlay {
		return fmt.Errorf("overlay flag is incompatible with shared file access")
	}
	if c.NumNetworkChannels <= 0 {
		return fmt.Errorf("num_network_channels must be > 0, got: %d", c.NumNetworkChannels)
	}
	// Require profile flags to explicitly opt-in to profiling with
	// -profile rather than implying it since these options have security
	// implications.
	if c.ProfileBlock != "" && !c.ProfileEnable {
		return fmt.Errorf("profile-block flag requires enabling profiling with profile flag")
	}
	if c.ProfileCPU != "" && !c.ProfileEnable {
		return fmt.Errorf("profile-cpu flag requires enabling profiling with profile flag")
	}
	if c.ProfileHeap != "" && !c.ProfileEnable {
		return fmt.Errorf("profile-heap flag requires enabling profiling with profile flag")
	}
	if c.ProfileMutex != "" && !c.ProfileEnable {
		return fmt.Errorf("profile-mutex flag requires enabling profiling with profile flag")
	}
	return nil
}

// FileAccessType tells how the filesystem is accessed.
type FileAccessType int

const (
	// FileAccessExclusive gives the sandbox exclusive access over files and
	// directories in the filesystem. No external modifications are permitted and
	// can lead to undefined behavior.
	//
	// Exclusive filesystem access enables more aggressive caching and offers
	// significantly better performance. This is the default mode for the root
	// volume.
	FileAccessExclusive FileAccessType = iota

	// FileAccessShared is used for volumes that can have external changes. It
	// requires revalidation on every filesystem access to detect external
	// changes, and reduces the amount of caching that can be done. This is the
	// default mode for non-root volumes.
	FileAccessShared
)

func fileAccessTypePtr(v FileAccessType) *FileAccessType {
	return &v
}

// Set implements flag.Value.
func (f *FileAccessType) Set(v string) error {
	switch v {
	case "shared":
		*f = FileAccessShared
	case "exclusive":
		*f = FileAccessExclusive
	default:
		return fmt.Errorf("invalid file access type %q", v)
	}
	return nil
}

// Get implements flag.Value.
func (f *FileAccessType) Get() interface{} {
	return *f
}

// String implements flag.Value.
func (f FileAccessType) String() string {
	switch f {
	case FileAccessShared:
		return "shared"
	case FileAccessExclusive:
		return "exclusive"
	}
	panic(fmt.Sprintf("Invalid file access type %d", f))
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

func networkTypePtr(v NetworkType) *NetworkType {
	return &v
}

// Set implements flag.Value.
func (n *NetworkType) Set(v string) error {
	switch v {
	case "sandbox":
		*n = NetworkSandbox
	case "host":
		*n = NetworkHost
	case "none":
		*n = NetworkNone
	default:
		return fmt.Errorf("invalid network type %q", v)
	}
	return nil
}

// Get implements flag.Value.
func (n *NetworkType) Get() interface{} {
	return *n
}

// String implements flag.Value.
func (n NetworkType) String() string {
	switch n {
	case NetworkSandbox:
		return "sandbox"
	case NetworkHost:
		return "host"
	case NetworkNone:
		return "none"
	}
	panic(fmt.Sprintf("Invalid network type %d", n))
}

// QueueingDiscipline is used to specify the kind of Queueing Discipline to
// apply for a give FDBasedLink.
type QueueingDiscipline int

const (
	// QDiscNone disables any queueing for the underlying FD.
	QDiscNone QueueingDiscipline = iota

	// QDiscFIFO applies a simple fifo based queue to the underlying FD.
	QDiscFIFO
)

func queueingDisciplinePtr(v QueueingDiscipline) *QueueingDiscipline {
	return &v
}

// Set implements flag.Value.
func (q *QueueingDiscipline) Set(v string) error {
	switch v {
	case "none":
		*q = QDiscNone
	case "fifo":
		*q = QDiscFIFO
	default:
		return fmt.Errorf("invalid qdisc %q", v)
	}
	return nil
}

// Get implements flag.Value.
func (q *QueueingDiscipline) Get() interface{} {
	return *q
}

// String implements flag.Value.
func (q QueueingDiscipline) String() string {
	switch q {
	case QDiscNone:
		return "none"
	case QDiscFIFO:
		return "fifo"
	}
	panic(fmt.Sprintf("Invalid qdisc %d", q))
}

// controlConfig represents control endpoints.
type controlConfig struct {
	Controls *controlpb.ControlConfig
}

// Set implements flag.Value.
func (c *controlConfig) Set(v string) error {
	controls := strings.Split(v, ",")
	var controlList []controlpb.ControlConfig_Endpoint
	for _, control := range controls {
		switch control {
		case "EVENTS":
			controlList = append(controlList, controlpb.ControlConfig_EVENTS)
		case "FS":
			controlList = append(controlList, controlpb.ControlConfig_FS)
		case "LIFECYCLE":
			controlList = append(controlList, controlpb.ControlConfig_LIFECYCLE)
		case "LOGGING":
			controlList = append(controlList, controlpb.ControlConfig_LOGGING)
		case "PROFILE":
			controlList = append(controlList, controlpb.ControlConfig_PROFILE)
		case "USAGE":
			controlList = append(controlList, controlpb.ControlConfig_USAGE)
		case "PROC":
			controlList = append(controlList, controlpb.ControlConfig_PROC)
		case "STATE":
			controlList = append(controlList, controlpb.ControlConfig_STATE)
		case "DEBUG":
			controlList = append(controlList, controlpb.ControlConfig_DEBUG)
		default:
			return fmt.Errorf("invalid control %q", control)
		}
	}
	c.Controls.AllowedControls = controlList
	return nil
}

// Get implements flag.Value.
func (c *controlConfig) Get() interface{} {
	return *c
}

// String implements flag.Value.
func (c *controlConfig) String() string {
	v := ""
	for _, control := range c.Controls.GetAllowedControls() {
		if len(v) > 0 {
			v += ","
		}
		switch control {
		case controlpb.ControlConfig_EVENTS:
			v += "EVENTS"
		case controlpb.ControlConfig_FS:
			v += "FS"
		case controlpb.ControlConfig_LIFECYCLE:
			v += "LIFECYCLE"
		case controlpb.ControlConfig_LOGGING:
			v += "LOGGING"
		case controlpb.ControlConfig_PROFILE:
			v += "PROFILE"
		case controlpb.ControlConfig_USAGE:
			v += "USAGE"
		case controlpb.ControlConfig_PROC:
			v += "PROC"
		case controlpb.ControlConfig_STATE:
			v += "STATE"
		case controlpb.ControlConfig_DEBUG:
			v += "DEBUG"
		default:
			panic(fmt.Sprintf("Invalid control %d", control))
		}
	}
	return v
}

func defaultControlConfig() *controlConfig {
	c := controlConfig{}
	c.Controls = &controlpb.ControlConfig{}
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_EVENTS)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_FS)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_LIFECYCLE)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_LOGGING)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_PROFILE)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_USAGE)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_PROC)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_STATE)
	c.Controls.AllowedControls = append(c.Controls.AllowedControls, controlpb.ControlConfig_DEBUG)
	return &c
}

func leakModePtr(v refs.LeakMode) *refs.LeakMode {
	return &v
}

func watchdogActionPtr(v watchdog.Action) *watchdog.Action {
	return &v
}
