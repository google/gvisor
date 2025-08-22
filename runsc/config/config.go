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
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/version"
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
	// If specified together with `DebugToUserLog`, debug logs are emitted
	// to both.
	DebugLog string `flag:"debug-log"`

	// DebugToUserLog indicates that Sentry debug logs should be emitted
	// to user-visible logs.
	// If specified together with `DebugLog`, debug logs are emitted
	// to both.
	DebugToUserLog bool `flag:"debug-to-user-log"`

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

	// HostSettings controls how host settings are handled.
	HostSettings HostSettingsPolicy `flag:"host-settings"`

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

	// GVisorGSO indicates that gVisor segmentation offload is enabled. The flag
	// retains its old name of "software" GSO for API consistency.
	GVisorGSO bool `flag:"software-gso"`

	// GVisorGRO enables gVisor's generic receive offload.
	GVisorGRO bool `flag:"gvisor-gro"`

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

	// MetricServer, if set, indicates that metrics should be exported on this address.
	// This may either be 1) "addr:port" to export metrics on a specific network interface address,
	// 2) ":port" for exporting metrics on all addresses, or 3) an absolute path to a Unix Domain
	// Socket.
	// The substring "%ID%" will be replaced by the container ID, and "%RUNTIME_ROOT%" by the root.
	// This flag must be specified *both* as part of the `runsc metric-server` arguments (so that the
	// metric server knows which address to bind to), and as part of the `runsc create` arguments (as
	// an indication that the container being created wishes that its metrics should be exported).
	// The value of this flag must also match across the two command lines.
	MetricServer string `flag:"metric-server"`

	// FinalMetricsLog is the file to which all metric data should be written
	// upon sandbox termination.
	FinalMetricsLog string `flag:"final-metrics-log"`

	// ProfilingMetrics is a comma separated list of metric names which are
	// going to be written to the ProfilingMetricsLog file from within the
	// sentry in CSV format. ProfilingMetrics will be snapshotted at a rate
	// specified by ProfilingMetricsRate. Requires ProfilingMetricsLog to be
	// set.
	ProfilingMetrics string `flag:"profiling-metrics"`

	// ProfilingMetricsLog is the file name to use for ProfilingMetrics
	// output.
	ProfilingMetricsLog string `flag:"profiling-metrics-log"`

	// ProfilingMetricsRate is the target rate (in microseconds) at which
	// profiling metrics will be snapshotted.
	ProfilingMetricsRate int `flag:"profiling-metrics-rate-us"`

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

	// ProfileGCInterval forces a garbage-collection cycle at regular intervals.
	// Useful for benchmark runs where the GC threshold may not be reached
	// but for which it is useful to have GC (and the effects of GC) show
	// up in the traces, while keeping the profile short.
	// Requires `ProfileEnable`, and triggered when any other type of
	// time-based profiling is enabled.
	// If zero, GC happens per the Go runtime's default behavior.
	ProfileGCInterval time.Duration `flag:"profile-gc-interval"`

	// ProfileHeap collects a heap profile to the passed file for the
	// duration of the container execution. Requires ProfileEnabled.
	ProfileHeap string `flag:"profile-heap"`

	// ProfileMutex collects a mutex profile to the passed file for the
	// duration of the container execution. Requires ProfileEnabled.
	ProfileMutex string `flag:"profile-mutex"`

	// TraceFile collects a Go runtime execution trace to the passed file
	// for the duration of the container execution.
	TraceFile string `flag:"trace"`

	// NumNetworkChannels controls the number of AF_PACKET sockets that map
	// to the same underlying network device. This allows netstack to better
	// scale for high throughput use cases.
	NumNetworkChannels int `flag:"num-network-channels"`

	// NetworkProcessorsPerChannel controls the number of goroutines used to
	// handle packets on a single network channel. A higher number can help handle
	// many simultaneous connections. If this is 0, runsc will divide GOMAXPROCS
	// evenly among each network channel.
	NetworkProcessorsPerChannel int `flag:"network-processors-per-channel"`

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

	// Allows overriding of flags in OCI annotations.
	AllowFlagOverride bool `flag:"allow-flag-override"`

	// Enables seccomp inside the sandbox.
	OCISeccomp bool `flag:"oci-seccomp"`

	// Don't configure cgroups.
	IgnoreCgroups bool `flag:"ignore-cgroups"`

	// Use systemd to configure cgroups.
	SystemdCgroup bool `flag:"systemd-cgroup"`

	// PodInitConfig is the path to configuration file with additional steps to
	// take during pod creation.
	PodInitConfig string `flag:"pod-init-config"`

	// Use pools to manage buffer memory instead of heap.
	BufferPooling bool `flag:"buffer-pooling"`

	// XDP controls Whether and how to use XDP.
	XDP XDP `flag:"EXPERIMENTAL-xdp"`

	// AFXDPUseNeedWakeup determines whether XDP_USE_NEED_WAKEUP is set
	// when using AF_XDP sockets.
	AFXDPUseNeedWakeup bool `flag:"EXPERIMENTAL-xdp-need-wakeup"`

	// FDLimit specifies a limit on the number of host file descriptors that can
	// be open simultaneously by the sentry and gofer. It applies separately to
	// each.
	FDLimit int `flag:"fdlimit"`

	// DCache sets the global dirent cache size. If negative, per-mount caches are
	// used.
	DCache int `flag:"dcache"`

	// IOUring enables support for the IO_URING API calls to perform
	// asynchronous I/O operations.
	IOUring bool `flag:"iouring"`

	// DirectFS sets up the sandbox to directly access/mutate the filesystem from
	// the sentry. Sentry runs with escalated privileges. Gofer process still
	// exists, but is mostly idle. Not supported in rootless mode.
	DirectFS bool `flag:"directfs"`

	// AppHugePages enables support for application huge pages.
	AppHugePages bool `flag:"app-huge-pages"`

	// NVProxy enables support for Nvidia GPUs.
	NVProxy bool `flag:"nvproxy"`

	// NVProxyDocker is deprecated. Please use nvidia-container-runtime or
	// `docker run --gpus` directly. For backward compatibility, this has the
	// effect of injecting nvidia-container-runtime-hook as a prestart hook.
	NVProxyDocker bool `flag:"nvproxy-docker"`

	// NVProxyDriverVersion is the version of the NVIDIA driver ABI to use.
	// If empty, it is autodetected from the installed NVIDIA driver.
	// It can also be set to the special value "latest" to force the use of
	// the latest supported NVIDIA driver ABI.
	NVProxyDriverVersion string `flag:"nvproxy-driver-version"`

	// NVProxyAllowUnsupportedCapabilities is a comma-separated list of driver
	// capabilities that are allowed to be requested by the container.
	NVProxyAllowedDriverCapabilities string `flag:"nvproxy-allowed-driver-capabilities"`

	// TPUProxy enables support for TPUs.
	TPUProxy bool `flag:"tpuproxy"`

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

	// TestOnlyAFSSyscallPanic should only be used in tests. It enables the
	// alternate behaviour for afs_syscall to trigger a Go-runtime panic upon being
	// called. This is useful for tests exercising gVisor panic-reporting.
	TestOnlyAFSSyscallPanic bool `flag:"TESTONLY-afs-syscall-panic"`

	// explicitlySet contains whether a flag was explicitly set on the command-line from which this
	// Config was constructed. Nil when the Config was not initialized from a FlagSet.
	explicitlySet map[string]struct{}

	// ReproduceNAT, when true, tells runsc to scrape the host network
	// namespace's NAT iptables and reproduce it inside the sandbox.
	ReproduceNAT bool `flag:"reproduce-nat"`

	// ReproduceNftables attempts to scrape nftables routing rules if
	// present, and reproduce them in the sandbox.
	ReproduceNftables bool `flag:"reproduce-nftables"`

	// Indicates whether open network connections and open unix domain
	// sockets should be disconnected upon save."
	NetDisconnectOk bool `flag:"net-disconnect-ok"`

	// TestOnlyAutosaveImagePath if not empty enables auto save for syscall tests
	// and stores the directory path to the saved state file.
	TestOnlyAutosaveImagePath string `flag:"TESTONLY-autosave-image-path"`

	// TestOnlyAutosaveResume indicates save resume for syscall tests.
	TestOnlyAutosaveResume bool `flag:"TESTONLY-autosave-resume"`

	// RestoreSpecValidation indicates the level of spec validation to be
	// performed during restore.
	RestoreSpecValidation RestoreSpecValidationPolicy `flag:"restore-spec-validation"`

	// GVisorMarkerFile enables the /proc/gvisor/kernel_is_gvisor marker file.
	GVisorMarkerFile bool `flag:"gvisor-marker-file"`

	// SystrapDisableSyscallPatching disables syscall patching in Systrap.
	SystrapDisableSyscallPatching bool `flag:"systrap-disable-syscall-patching"`

	// SaveRestoreNetstack indicates whether netstack should be saved and restored.
	SaveRestoreNetstack bool `flag:"save-restore-netstack"`

	// Nftables enables support for nftables to be used instead of iptables.
	Nftables bool `flag:"TESTONLY-nftables"`

	// AllowSUID causes ID elevation to be allowed when execving into executables
	// with the SUID/SGID bits set.
	AllowSUID bool `flag:"allow-suid"`
}

func (c *Config) validate() error {
	if c.Overlay && c.Overlay2.Enabled() {
		// Deprecated flag was used together with flag that replaced it.
		return fmt.Errorf("overlay flag has been replaced with overlay2 flag")
	}
	if overlay2 := c.GetOverlay2(); c.FileAccess == FileAccessShared && overlay2.Enabled() {
		return fmt.Errorf("overlay flag is incompatible with shared file access for rootfs")
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
	if len(c.ProfilingMetrics) > 0 && len(c.ProfilingMetricsLog) == 0 {
		return fmt.Errorf("profiling-metrics flag requires defining a profiling-metrics-log for output")
	}
	allowedCaps, _, err := nvconf.DriverCapsFromString(c.NVProxyAllowedDriverCapabilities)
	if err != nil {
		return fmt.Errorf("--nvproxy-allowed-driver-capabilities=%q: %w", c.NVProxyAllowedDriverCapabilities, err)
	}
	if unsupported := allowedCaps & ^nvconf.SupportedDriverCaps; unsupported != 0 {
		return fmt.Errorf("--nvproxy-allowed-driver-capabilities=%q: unsupported capabilities: %v", c.NVProxyAllowedDriverCapabilities, unsupported)
	}
	return nil
}

// Log logs important aspects of the configuration to the given log function.
func (c *Config) Log() {
	log.Infof("Platform: %v", c.Platform)
	log.Infof("RootDir: %s", c.RootDir)
	log.Infof("FileAccess: %v / Directfs: %t / Overlay: %v", c.FileAccess, c.DirectFS, c.GetOverlay2())
	log.Infof("Network: %v", c.Network)
	if c.Debug || c.Strace {
		log.Infof("Debug: %t. Strace: %t, max size: %d, syscalls: %s", c.Debug, c.Strace, c.StraceLogSize, c.StraceSyscalls)
	}
	if !c.AllowSUID {
		log.Warningf("--allow-suid is disabled, SUID/SGID bits on executables will be ignored.")
	}
	if c.Debug {
		obj := reflect.ValueOf(c).Elem()
		st := obj.Type()
		for i := 0; i < st.NumField(); i++ {
			f := st.Field(i)
			var val any
			if strVal := obj.Field(i).String(); strVal == "" {
				val = "(empty)"
			} else if !f.IsExported() {
				// Cannot convert to `interface{}` for non-exported fields,
				// so just use `strVal`.
				val = fmt.Sprintf("%s (unexported)", strVal)
			} else {
				val = obj.Field(i).Interface()
			}
			if flagName, hasFlag := f.Tag.Lookup("flag"); hasFlag {
				log.Debugf("Config.%s (--%s): %v", f.Name, flagName, val)
			} else {
				log.Debugf("Config.%s: %v", f.Name, val)
			}
		}
	}
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
		// Using a deprecated flag, honor it to avoid breaking users.
		return Overlay2{rootMount: true, subMounts: true, medium: "memory"}
	}
	return c.Overlay2
}

// Bundle is a set of flag name-value pairs.
type Bundle map[string]string

// BundleName is a human-friendly name for a Bundle.
// It is used as part of an annotation to specify that the user wants to apply a Bundle.
type BundleName string

// Validate validates that given flag string values map to actual flags in runsc.
func (b Bundle) Validate() error {
	flagSet := flag.NewFlagSet("tmp", flag.ContinueOnError)
	RegisterFlags(flagSet)
	for key, val := range b {
		flag := flagSet.Lookup(key)
		if flag == nil {
			return fmt.Errorf("unknown flag %q", key)
		}
		if err := flagSet.Set(key, val); err != nil {
			return err
		}
	}
	return nil
}

// MetricMetadataKeys is the set of keys of metric metadata labels
// as returned by `Config.MetricMetadata`.
var MetricMetadataKeys = []string{
	"version",
	"platform",
	"network",
	"numcores",
	"coretags",
	"overlay",
	"fsmode",
	"cpuarch",
	"go",
	"experiment",
}

// MetricMetadata returns key-value pairs that are useful to include in metrics
// exported about the sandbox this config represents.
// It must return the same set of labels as listed in `MetricMetadataKeys`.
func (c *Config) MetricMetadata() map[string]string {
	var fsMode = "goferfs"
	if c.DirectFS {
		fsMode = "directfs"
	}
	return map[string]string{
		"version":  version.Version(),
		"platform": c.Platform,
		"network":  c.Network.String(),
		"numcores": strconv.Itoa(runtime.NumCPU()),
		"coretags": strconv.FormatBool(c.EnableCoreTags),
		"overlay":  c.Overlay2.String(),
		"fsmode":   fsMode,
		"cpuarch":  runtime.GOARCH,
		"go":       runtime.Version(),
		// The "experiment" label is currently unused, but may be used to contain
		// extra information about e.g. an experiment that may be enabled.
		"experiment": "",
	}
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

// Set implements flag.Value. Set(String()) should be idempotent.
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

	// NetworkPlugin uses third-party network stack.
	NetworkPlugin
)

func networkTypePtr(v NetworkType) *NetworkType {
	return &v
}

// Set implements flag.Value. Set(String()) should be idempotent.
func (n *NetworkType) Set(v string) error {
	switch v {
	case "sandbox":
		*n = NetworkSandbox
	case "host":
		*n = NetworkHost
	case "none":
		*n = NetworkNone
	case "plugin":
		*n = NetworkPlugin
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
	case NetworkPlugin:
		return "plugin"
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

// Set implements flag.Value. Set(String()) should be idempotent.
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

// Set implements flag.Value. Set(String()) should be idempotent.
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
	switch g {
	case HostUDSNone:
		return "none"
	case HostUDSOpen:
		return "open"
	case HostUDSCreate:
		return "create"
	case HostUDSAll:
		return "all"
	default:
		panic(fmt.Sprintf("Invalid host UDS type %d", g))
	}
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

// Set implements flag.Value. Set(String()) should be idempotent.
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
	switch g {
	case HostFifoNone:
		return "none"
	case HostFifoOpen:
		return "open"
	default:
		panic(fmt.Sprintf("Invalid host fifo type %d", g))
	}
}

// AllowOpen returns true if it can consume FIFOs from the host.
func (g HostFifo) AllowOpen() bool {
	return g&HostFifoOpen != 0
}

// OverlayMedium describes how overlay medium is configured.
type OverlayMedium string

const (
	// NoOverlay indicates that no overlay will be applied.
	NoOverlay = OverlayMedium("")

	// MemoryOverlay indicates that the overlay is backed by app memory.
	MemoryOverlay = OverlayMedium("memory")

	// SelfOverlay indicates that the overlaid mount is backed by itself.
	SelfOverlay = OverlayMedium("self")

	// AnonOverlayPrefix is the prefix that users should specify in the
	// config for the anonymous overlay.
	AnonOverlayPrefix = "dir="
)

// String returns a human-readable string representing the overlay medium config.
func (m OverlayMedium) String() string {
	return string(m)
}

// Set sets the value. Set(String()) should be idempotent.
func (m *OverlayMedium) Set(v string) error {
	switch OverlayMedium(v) {
	case NoOverlay, MemoryOverlay, SelfOverlay: // OK
	default:
		if !strings.HasPrefix(v, AnonOverlayPrefix) {
			return fmt.Errorf("unexpected medium: %q", v)
		}
		if hostFileDir := strings.TrimPrefix(v, AnonOverlayPrefix); !filepath.IsAbs(hostFileDir) {
			return fmt.Errorf("overlay host file directory should be an absolute path, got %q", hostFileDir)
		}
	}
	*m = OverlayMedium(v)
	return nil
}

// IsBackedByAnon indicates whether the overlaid mount is backed by a host file
// in an anonymous directory.
func (m OverlayMedium) IsBackedByAnon() bool {
	return strings.HasPrefix(string(m), AnonOverlayPrefix)
}

// HostFileDir indicates the directory in which the overlay-backing host file
// should be created.
//
// Precondition: m.IsBackedByAnon().
func (m OverlayMedium) HostFileDir() string {
	if !m.IsBackedByAnon() {
		panic(fmt.Sprintf("anonymous overlay medium = %q does not have %v prefix", m, AnonOverlayPrefix))
	}
	return strings.TrimPrefix(string(m), AnonOverlayPrefix)
}

// Overlay2 holds the configuration for setting up overlay filesystems for the
// container.
type Overlay2 struct {
	rootMount bool
	subMounts bool
	medium    OverlayMedium
	// Size of overlay upper layer.
	// Passed as is to tmpfs mount, as `size={size}`.
	// Empty means use default.
	// Size is applied to each overlay independently and not shared by overlays.
	size string
}

func defaultOverlay2() *Overlay2 {
	// Rootfs overlay is enabled by default and backed by a file in rootfs itself.
	return &Overlay2{rootMount: true, subMounts: false, medium: SelfOverlay}
}

func setOverlay2Err(v string) error {
	return fmt.Errorf("expected format is --overlay2={mount}:{medium}[,size={size}], got %q", v)
}

// `--overlay2=...` param `size=`.
const overlay2SizeEq = "size="

// Set implements flag.Value. Set(String()) should be idempotent.
func (o *Overlay2) Set(v string) error {
	if v == "none" {
		o.rootMount = false
		o.subMounts = false
		o.medium = NoOverlay
		o.size = ""
		return nil
	}
	parts := strings.Split(v, ",")
	if len(parts) < 1 {
		return setOverlay2Err(v)
	}

	vs := strings.Split(parts[0], ":")
	if len(vs) != 2 {
		return setOverlay2Err(v)
	}

	switch mount := vs[0]; mount {
	case "root":
		o.rootMount = true
	case "all":
		o.rootMount = true
		o.subMounts = true
	default:
		return fmt.Errorf("unexpected mount specifier for --overlay2: %q", mount)
	}

	err := o.medium.Set(vs[1])
	if err != nil {
		return err
	}

	if len(parts) == 1 {
		o.size = ""
	} else if len(parts) == 2 {
		sizeArg := parts[1]
		size, cut := strings.CutPrefix(sizeArg, overlay2SizeEq)
		if !cut {
			return setOverlay2Err(v)
		}
		o.size = size
	} else {
		return setOverlay2Err(v)
	}

	return nil
}

// Get implements flag.Value.
func (o *Overlay2) Get() any {
	return *o
}

// String implements flag.Value.
func (o Overlay2) String() string {
	if !o.rootMount && !o.subMounts {
		return "none"
	}
	res := ""
	switch {
	case o.rootMount && o.subMounts:
		res = "all"
	case o.rootMount:
		res = "root"
	default:
		panic("invalid state of subMounts = true and rootMount = false")
	}

	var sizeSuffix string
	if o.size != "" {
		sizeSuffix = fmt.Sprintf(",%s%s", overlay2SizeEq, o.size)
	}

	return res + ":" + o.medium.String() + sizeSuffix
}

// Enabled returns true if the overlay option is enabled for any mounts.
func (o *Overlay2) Enabled() bool {
	return o.medium != NoOverlay
}

// RootOverlayMedium returns the overlay medium config of the root mount.
func (o *Overlay2) RootOverlayMedium() OverlayMedium {
	if !o.rootMount {
		return NoOverlay
	}
	return o.medium
}

func (o *Overlay2) RootOverlaySize() string {
	if !o.rootMount {
		return ""
	}
	return o.size
}

// SubMountOverlayMedium returns the overlay medium config of submounts.
func (o *Overlay2) SubMountOverlayMedium() OverlayMedium {
	if !o.subMounts {
		return NoOverlay
	}
	return o.medium
}

func (o *Overlay2) SubMountOverlaySize() string {
	if !o.subMounts {
		return ""
	}
	return o.size
}

// Medium returns the overlay medium config.
func (o Overlay2) Medium() OverlayMedium {
	return o.medium
}

// HostSettingsPolicy dictates how host settings should be handled.
type HostSettingsPolicy int

// HostSettingsPolicy values.
const (
	// HostSettingsCheck checks the host settings. If any are not optimal, it
	// will fail if any of them are mandatory, but will otherwise only log
	// warnings. It never attempts to modify host settings.
	HostSettingsCheck HostSettingsPolicy = iota

	// HostSettingsCheck checks the host settings. If any are not optimal, it
	// will fail if any of them are mandatory, but will otherwise not log
	// anything about non-mandatory settings.
	// It never attempts to modify host settings.
	HostSettingsCheckMandatory

	// HostSettingsIgnore does not check nor adjust any host settings.
	// This is useful in case the host settings are already known to be
	// optimal, or to avoid errors if `runsc` is running within a seccomp
	// or AppArmor policy that prevents it from checking host settings.
	HostSettingsIgnore

	// HostSettingsAdjust automatically adjusts host settings if they are not
	// optimal. It will fail if any setting is mandatory but cannot be adjusted.
	// For non-mandatory settings, it logs a warning if adjustment fails.
	HostSettingsAdjust

	// HostSettingsEnforce automatically adjusts host settings if they are not
	// optimal, and fails if adjustment of any setting fails.
	HostSettingsEnforce
)

// Set implements flag.Value. Set(String()) should be idempotent.
func (p *HostSettingsPolicy) Set(v string) error {
	switch v {
	case "check":
		*p = HostSettingsCheck
	case "check_mandatory":
		*p = HostSettingsCheckMandatory
	case "ignore":
		*p = HostSettingsIgnore
	case "adjust":
		*p = HostSettingsAdjust
	case "enforce":
		*p = HostSettingsEnforce
	default:
		return fmt.Errorf("invalid host settings policy %q", v)
	}
	return nil
}

// Ptr returns a pointer to `p`.
// Useful in flag declaration line.
func (p HostSettingsPolicy) Ptr() *HostSettingsPolicy {
	return &p
}

// Get implements flag.Get.
func (p *HostSettingsPolicy) Get() any {
	return *p
}

// String implements flag.String.
func (p HostSettingsPolicy) String() string {
	switch p {
	case HostSettingsCheck:
		return "check"
	case HostSettingsCheckMandatory:
		return "check_mandatory"
	case HostSettingsAdjust:
		return "adjust"
	case HostSettingsIgnore:
		return "ignore"
	case HostSettingsEnforce:
		return "enforce"
	default:
		panic(fmt.Sprintf("Invalid host settings policy %d", p))
	}
}

// RestoreSpecValidationPolicy dictates how spec validation should be handled.
type RestoreSpecValidationPolicy int

// RestoreSpecValidationPolicy values.
const (
	// RestoreSpecValidationIgnore does not validate the spec during restore.
	RestoreSpecValidationIgnore RestoreSpecValidationPolicy = iota

	// RestoreSpecValidationWarning will perform spec validation and logs a warning
	// if the validation fails, however the restore will continue.
	RestoreSpecValidationWarning

	// RestoreSpecValidationEnforce will perform spec validation and returns an
	// error if the validation fails and aborts restoring the containers.
	RestoreSpecValidationEnforce
)

// Set implements flag.Value. Set(String()) should be idempotent.
func (p *RestoreSpecValidationPolicy) Set(v string) error {
	switch v {
	case "ignore":
		*p = RestoreSpecValidationIgnore
	case "warning":
		*p = RestoreSpecValidationWarning
	case "enforce":
		*p = RestoreSpecValidationEnforce
	default:
		return fmt.Errorf("invalid restore spec validation policy %q", v)
	}
	return nil
}

// Ptr returns a pointer to `p`.
// Useful in flag declaration line.
func (p RestoreSpecValidationPolicy) Ptr() *RestoreSpecValidationPolicy {
	return &p
}

// Get implements flag.Get.
func (p *RestoreSpecValidationPolicy) Get() any {
	return *p
}

// String implements flag.String.
func (p RestoreSpecValidationPolicy) String() string {
	switch p {
	case RestoreSpecValidationIgnore:
		return "ignore"
	case RestoreSpecValidationWarning:
		return "warning"
	case RestoreSpecValidationEnforce:
		return "enforce"
	default:
		panic(fmt.Sprintf("invalid restore spec validation policy %d", p))
	}
}

// XDP holds configuration for whether and how to use XDP.
type XDP struct {
	Mode      XDPMode
	IfaceName string
}

// XDPMode specifies a particular use of XDP.
type XDPMode int

const (
	// XDPModeOff doesn't use XDP.
	XDPModeOff XDPMode = iota

	// XDPModeNS uses an AF_XDP socket to read from the VETH device inside
	// the container's network namespace.
	XDPModeNS

	// XDPModeRedirect uses an AF_XDP socket on the host NIC to bypass the
	// Linux network stack.
	XDPModeRedirect

	// XDPModeTunnel uses XDP_REDIRECT to redirect packets directly from the
	// host NIC to the VETH device inside the container's network
	// namespace. Packets are read from the VETH via AF_XDP, as in
	// XDPModeNS.
	XDPModeTunnel
)

const (
	xdpModeStrOff      = "off"
	xdpModeStrNS       = "ns"
	xdpModeStrRedirect = "redirect"
	xdpModeStrTunnel   = "tunnel"
)

var xdpConfig XDP

// Get implements flag.Getter.
func (xd *XDP) Get() any {
	return *xd
}

// String implements flag.Getter.
func (xd *XDP) String() string {
	switch xd.Mode {
	case XDPModeOff:
		return xdpModeStrOff
	case XDPModeNS:
		return xdpModeStrNS
	case XDPModeRedirect:
		return fmt.Sprintf("%s:%s", xdpModeStrRedirect, xd.IfaceName)
	case XDPModeTunnel:
		return fmt.Sprintf("%s:%s", xdpModeStrTunnel, xd.IfaceName)
	default:
		panic(fmt.Sprintf("unknown mode %d", xd.Mode))
	}
}

// Set implements flag.Getter.
func (xd *XDP) Set(input string) error {
	parts := strings.Split(input, ":")
	if len(parts) > 2 {
		return fmt.Errorf("invalid --xdp value: %q", input)
	}

	switch {
	case input == xdpModeStrOff:
		xd.Mode = XDPModeOff
		xd.IfaceName = ""
	case input == xdpModeStrNS:
		xd.Mode = XDPModeNS
		xd.IfaceName = ""
	case len(parts) == 2 && parts[0] == xdpModeStrRedirect && parts[1] != "":
		xd.Mode = XDPModeRedirect
		xd.IfaceName = parts[1]
	case len(parts) == 2 && parts[0] == xdpModeStrTunnel && parts[1] != "":
		xd.Mode = XDPModeTunnel
		xd.IfaceName = parts[1]
	default:
		return fmt.Errorf("invalid --xdp value: %q", input)
	}
	return nil
}
