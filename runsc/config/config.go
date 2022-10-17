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
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
)

// Config holds configuration that is not part of the runtime spec.
//
// Follow these steps to add a new flag:
//  1. Create a new field in Config.
//  2. Add a field tag with the flag name
//  3. Register a new flag in flags.go, with same name and add a description
//  4. Add any necessary validation into validate()
//  5. If adding an enum, follow the same pattern as FileAccessType
//  6. Evaluate if the flag can be changed with OCI annotations. See
//     overrideAllowlist for more details
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

	// DebugCommand is a comma-separated list of commands to be debugged if
	// --debug-log is also set. Empty means debug all. "!" negates the expression.
	// E.g. "create,start" or "!boot,events".
	DebugCommand string `flag:"debug-command"`

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

	// Overlay is whether to wrap all mounts in an overlay. The upper tmpfs layer
	// will be backed by application memory.
	Overlay bool `flag:"overlay"`

	// Overlay2 holds configuration about wrapping mounts in overlayfs.
	// DO NOT call it directly, use GetOverlay2() instead.
	Overlay2 Overlay2 `flag:"overlay2"`

	// FSGoferHostUDS is deprecated: use host-uds=all.
	FSGoferHostUDS bool `flag:"fsgofer-host-uds"`

	// HostUDS controls permission to access host Unix-domain sockets.
	// DO NOT call it directly, use GetHostUDS() instead.
	HostUDS HostUDS `flag:"host-uds"`

	// HostFifo controls permission to access host FIFO (or named pipes).
	HostFifo HostFifo `flag:"host-fifo"`

	// Network indicates what type of network to use.
	Network NetworkType `flag:"network"`

	// EnableRaw indicates whether raw sockets should be enabled. Raw
	// sockets are disabled by stripping CAP_NET_RAW from the list of
	// capabilities.
	EnableRaw bool `flag:"net-raw"`

	// AllowPacketEndpointWrite enables write operations on packet endpoints.
	AllowPacketEndpointWrite bool `flag:"TESTONLY-allow-packet-endpoint-write"`

	// HostGSO indicates that host segmentation offload is enabled.
	HostGSO bool `flag:"gso"`

	// GvisorGSO indicates that gVisor segmentation offload is enabled. The flag
	// retains its old name of "software" GSO for API consistency.
	GvisorGSO bool `flag:"software-gso"`

	// GvisorGROTimeout sets gVisor's generic receive offload timeout. Zero
	// bypasses GRO.
	GvisorGROTimeout time.Duration `flag:"gvisor-gro"`

	// TXChecksumOffload indicates that TX Checksum Offload is enabled.
	TXChecksumOffload bool `flag:"tx-checksum-offload"`

	// RXChecksumOffload indicates that RX Checksum Offload is enabled.
	RXChecksumOffload bool `flag:"rx-checksum-offload"`

	// QDisc indicates the type of queuening discipline to use by default
	// for non-loopback interfaces.
	QDisc QueueingDiscipline `flag:"qdisc"`

	// LogPackets indicates that all network packets should be logged.
	LogPackets bool `flag:"log-packets"`

	// PCAP is a file to which network packets should be logged in PCAP format.
	PCAP string `flag:"pcap-log"`

	// Platform is the platform to run on.
	Platform string `flag:"platform"`

	// PlatformDevicePath is the path to the device file used by the platform.
	// e.g. "/dev/kvm" for the KVM platform.
	// If unset, a sane platform-specific default will be used.
	PlatformDevicePath string `flag:"platform_device_path"`

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

	// EnableCoreTags indicates whether the Sentry process and children will be
	// run in a core tagged process. This isolates the sentry from sharing
	// physical cores with other core tagged processes. This is useful as a
	// mitigation for hyperthreading side channel based attacks. Requires host
	// linux kernel >= 5.14.
	EnableCoreTags bool `flag:"enable-core-tags"`

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

	// RestoreFile is the path to the saved container image.
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

	// Enable lisafs.
	Lisafs bool `flag:"lisafs"`

	// Allows overriding of flags in OCI annotations.
	AllowFlagOverride bool `flag:"allow-flag-override"`

	// Enables seccomp inside the sandbox.
	OCISeccomp bool `flag:"oci-seccomp"`

	// Mounts the cgroup filesystem backed by the sentry's cgroupfs.
	Cgroupfs bool `flag:"cgroupfs"`

	// Don't configure cgroups.
	IgnoreCgroups bool `flag:"ignore-cgroups"`

	// Use systemd to configure cgroups.
	SystemdCgroup bool `flag:"systemd-cgroup"`

	// PodInitConfig is the path to configuration file with additional steps to
	// take during pod creation.
	PodInitConfig string `flag:"pod-init-config"`

	// Use pools to manage buffer memory instead of heap.
	BufferPooling bool `flag:"buffer-pooling"`

	// AFXDP defines whether to use an AF_XDP socket to receive packets
	// (rather than AF_PACKET). Enabling it disables RX checksum offload.
	AFXDP bool `flag:"EXPERIMENTAL-afxdp"`

	// FDLimit specifies a limit on the number of host file descriptors that can
	// be open simultaneously by the sentry and gofer. It applies separately to
	// each.
	FDLimit int `flag:"fdlimit"`

	// DCache sets the global dirent cache size. If zero, per-mount caches are
	// used.
	DCache int `flag:"dcache"`

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
	if c.Overlay && c.Overlay2.Enabled() {
		// Deprecated flag was used together with flag that replaced it.
		return fmt.Errorf("overlay flag has been replaced with overlay2 flag")
	}
	if overlay2 := c.GetOverlay2(); c.FileAccess == FileAccessShared && overlay2.Enabled() {
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
	if c.FSGoferHostUDS && c.HostUDS != HostUDSNone {
		// Deprecated flag was used together with flag that replaced it.
		return fmt.Errorf("fsgofer-host-uds has been replaced with host-uds flag")
	}
	return nil
}

// GetHostUDS returns the FS gofer communication that is allowed, taking into
// consideration all flags what affect the result.
func (c *Config) GetHostUDS() HostUDS {
	if c.FSGoferHostUDS {
		if c.HostUDS != HostUDSNone {
			panic(fmt.Sprintf("HostUDS cannot be set when --fsgofer-host-uds=true"))
		}
		// Using deprecated flag, honor it to avoid breaking users.
		return HostUDSOpen
	}
	return c.HostUDS
}

// GetOverlay2 returns the overlay configuration, taking into consideration all
// flags that affect the result.
func (c *Config) GetOverlay2() Overlay2 {
	if c.Overlay {
		if c.Overlay2.Enabled() {
			panic(fmt.Sprintf("Overlay2 cannot be set when --overlay=true"))
		}
		// Using deprecated flag, honor it to avoid breaking users.
		return Overlay2{RootMount: true, SubMounts: true, FilestoreDir: ""}
	}
	return c.Overlay2
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
func (f *FileAccessType) Get() any {
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
func (n *NetworkType) Get() any {
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
func (q *QueueingDiscipline) Get() any {
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

func leakModePtr(v refs.LeakMode) *refs.LeakMode {
	return &v
}

func watchdogActionPtr(v watchdog.Action) *watchdog.Action {
	return &v
}

// HostUDS tells how much of the host UDS the file system has access to.
type HostUDS int

const (
	// HostUDSNone doesn't allows UDS from the host to be manipulated.
	HostUDSNone HostUDS = 0x0

	// HostUDSOpen allows UDS from the host to be opened, e.g. connect(2).
	HostUDSOpen HostUDS = 0x1

	// HostUDSCreate allows UDS from the host to be created, e.g. bind(2).
	HostUDSCreate HostUDS = 0x2

	// HostUDSAll allows all form of communication with the host through UDS.
	HostUDSAll = HostUDSOpen | HostUDSCreate
)

func hostUDSPtr(v HostUDS) *HostUDS {
	return &v
}

// Set implements flag.Value.
func (g *HostUDS) Set(v string) error {
	switch v {
	case "", "none":
		*g = HostUDSNone
	case "open":
		*g = HostUDSOpen
	case "create":
		*g = HostUDSCreate
	case "all":
		*g = HostUDSAll
	default:
		return fmt.Errorf("invalid host UDS type %q", v)
	}
	return nil
}

// Get implements flag.Value.
func (g *HostUDS) Get() any {
	return *g
}

// String implements flag.Value.
func (g HostUDS) String() string {
	// Note: the order of operations is important given that HostUDS is a bitmap.
	if g == HostUDSNone {
		return "none"
	}
	if g == HostUDSAll {
		return "all"
	}
	if g == HostUDSOpen {
		return "open"
	}
	if g == HostUDSCreate {
		return "create"
	}
	panic(fmt.Sprintf("Invalid host UDS type %d", g))
}

// AllowOpen returns true if it can consume UDS from the host.
func (g HostUDS) AllowOpen() bool {
	return g&HostUDSOpen != 0
}

// AllowCreate returns true if it can create UDS in the host.
func (g HostUDS) AllowCreate() bool {
	return g&HostUDSCreate != 0
}

// HostFifo tells how much of the host FIFO (or named pipes) the file system has
// access to.
type HostFifo int

const (
	// HostFifoNone doesn't allow FIFO from the host to be manipulated.
	HostFifoNone HostFifo = 0x0

	// HostFifoOpen allows FIFOs from the host to be opened.
	HostFifoOpen HostFifo = 0x1
)

func hostFifoPtr(v HostFifo) *HostFifo {
	return &v
}

// Set implements flag.Value.
func (g *HostFifo) Set(v string) error {
	switch v {
	case "", "none":
		*g = HostFifoNone
	case "open":
		*g = HostFifoOpen
	default:
		return fmt.Errorf("invalid host fifo type %q", v)
	}
	return nil
}

// Get implements flag.Value.
func (g *HostFifo) Get() any {
	return *g
}

// String implements flag.Value.
func (g HostFifo) String() string {
	if g == HostFifoNone {
		return "none"
	}
	if g == HostFifoOpen {
		return "open"
	}
	panic(fmt.Sprintf("Invalid host fifo type %d", g))
}

// AllowOpen returns true if it can consume FIFOs from the host.
func (g HostFifo) AllowOpen() bool {
	return g&HostFifoOpen != 0
}

// Overlay2 holds the configuration for setting up overlay filesystems for the
// container.
type Overlay2 struct {
	RootMount    bool
	SubMounts    bool
	FilestoreDir string
}

func defaultOverlay2() *Overlay2 {
	return &Overlay2{}
}

// Set implements flag.Value.
func (o *Overlay2) Set(v string) error {
	if v == "none" {
		// Defaults are correct.
		return nil
	}
	vs := strings.Split(v, ":")
	if len(vs) != 2 {
		return fmt.Errorf("expected format is --overlay2={mount}:{medium}, got %q", v)
	}

	switch mount := vs[0]; mount {
	case "root":
		o.RootMount = true
	case "all":
		o.RootMount = true
		o.SubMounts = true
	default:
		return fmt.Errorf("unexpected mount specifier for --overlay2: %q", mount)
	}

	switch medium := vs[1]; medium {
	case "memory":
		o.FilestoreDir = ""
	default:
		o.FilestoreDir = medium
	}
	return nil
}

// Get implements flag.Value.
func (o *Overlay2) Get() any {
	return *o
}

// String implements flag.Value.
func (o Overlay2) String() string {
	if !o.RootMount && !o.SubMounts {
		return "none"
	}
	res := ""
	switch {
	case o.RootMount && o.SubMounts:
		res = "all"
	case o.RootMount:
		res = "root"
	default:
		panic("invalid state of subMounts = true and rootMount = false")
	}

	res += ":"
	switch o.FilestoreDir {
	case "":
		res += "memory"
	default:
		res += o.FilestoreDir
	}
	return res
}

// Enabled returns true if overlay option is enabled for any mounts.
func (o *Overlay2) Enabled() bool {
	return o.RootMount || o.SubMounts
}
