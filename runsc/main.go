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

// Binary runsc is an implementation of the Open Container Initiative Runtime
// that runs applications inside a sandbox.
package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/runsc/cmd"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

var (
	// Although these flags are not part of the OCI spec, they are used by
	// Docker, and thus should not be changed.
	rootDir     = flag.String("root", "", "root directory for storage of container state.")
	logFilename = flag.String("log", "", "file path where internal debug information is written, default is stdout.")
	logFormat   = flag.String("log-format", "text", "log format: text (default), json, or json-k8s.")
	debug       = flag.Bool("debug", false, "enable debug logging.")
	showVersion = flag.Bool("version", false, "show version and exit.")
	// TODO(gvisor.dev/issue/193): support systemd cgroups
	systemdCgroup = flag.Bool("systemd-cgroup", false, "Use systemd for cgroups. NOT SUPPORTED.")

	// These flags are unique to runsc, and are used to configure parts of the
	// system that are not covered by the runtime spec.

	// Debugging flags.
	debugLog        = flag.String("debug-log", "", "additional location for logs. If it ends with '/', log files are created inside the directory with default names. The following variables are available: %TIMESTAMP%, %COMMAND%.")
	panicLog        = flag.String("panic-log", "", "file path were panic reports and other Go's runtime messages are written.")
	logPackets      = flag.Bool("log-packets", false, "enable network packet logging.")
	logFD           = flag.Int("log-fd", -1, "file descriptor to log to.  If set, the 'log' flag is ignored.")
	debugLogFD      = flag.Int("debug-log-fd", -1, "file descriptor to write debug logs to.  If set, the 'debug-log-dir' flag is ignored.")
	panicLogFD      = flag.Int("panic-log-fd", -1, "file descriptor to write Go's runtime messages.")
	debugLogFormat  = flag.String("debug-log-format", "text", "log format: text (default), json, or json-k8s.")
	alsoLogToStderr = flag.Bool("alsologtostderr", false, "send log messages to stderr.")

	// Debugging flags: strace related
	strace         = flag.Bool("strace", false, "enable strace.")
	straceSyscalls = flag.String("strace-syscalls", "", "comma-separated list of syscalls to trace. If --strace is true and this list is empty, then all syscalls will be traced.")
	straceLogSize  = flag.Uint("strace-log-size", 1024, "default size (in bytes) to log data argument blobs.")

	// Flags that control sandbox runtime behavior.
	platformName       = flag.String("platform", "ptrace", "specifies which platform to use: ptrace (default), kvm.")
	network            = flag.String("network", "sandbox", "specifies which network to use: sandbox (default), host, none. Using network inside the sandbox is more secure because it's isolated from the host network.")
	hardwareGSO        = flag.Bool("gso", true, "enable hardware segmentation offload if it is supported by a network device.")
	softwareGSO        = flag.Bool("software-gso", true, "enable software segmentation offload when hardware offload can't be enabled.")
	txChecksumOffload  = flag.Bool("tx-checksum-offload", false, "enable TX checksum offload.")
	rxChecksumOffload  = flag.Bool("rx-checksum-offload", true, "enable RX checksum offload.")
	qDisc              = flag.String("qdisc", "fifo", "specifies which queueing discipline to apply by default to the non loopback nics used by the sandbox.")
	fileAccess         = flag.String("file-access", "exclusive", "specifies which filesystem to use for the root mount: exclusive (default), shared. Volume mounts are always shared.")
	fsGoferHostUDS     = flag.Bool("fsgofer-host-uds", false, "allow the gofer to mount Unix Domain Sockets.")
	overlay            = flag.Bool("overlay", false, "wrap filesystem mounts with writable overlay. All modifications are stored in memory inside the sandbox.")
	overlayfsStaleRead = flag.Bool("overlayfs-stale-read", true, "assume root mount is an overlay filesystem")
	watchdogAction     = flag.String("watchdog-action", "log", "sets what action the watchdog takes when triggered: log (default), panic.")
	panicSignal        = flag.Int("panic-signal", -1, "register signal handling that panics. Usually set to SIGUSR2(12) to troubleshoot hangs. -1 disables it.")
	profile            = flag.Bool("profile", false, "prepares the sandbox to use Golang profiler. Note that enabling profiler loosens the seccomp protection added to the sandbox (DO NOT USE IN PRODUCTION).")
	netRaw             = flag.Bool("net-raw", false, "enable raw sockets. When false, raw sockets are disabled by removing CAP_NET_RAW from containers (`runsc exec` will still be able to utilize raw sockets). Raw sockets allow malicious containers to craft packets and potentially attack the network.")
	numNetworkChannels = flag.Int("num-network-channels", 1, "number of underlying channels(FDs) to use for network link endpoints.")
	rootless           = flag.Bool("rootless", false, "it allows the sandbox to be started with a user that is not root. Sandbox and Gofer processes may run with same privileges as current user.")
	referenceLeakMode  = flag.String("ref-leak-mode", "disabled", "sets reference leak check mode: disabled (default), log-names, log-traces.")
	cpuNumFromQuota    = flag.Bool("cpu-num-from-quota", false, "set cpu number to cpu quota (least integer greater or equal to quota value, but not less than 2)")
	vfs2Enabled        = flag.Bool("vfs2", false, "TEST ONLY; use while VFSv2 is landing. This uses the new experimental VFS layer.")
	fuseEnabled        = flag.Bool("fuse", false, "TEST ONLY; use while FUSE in VFSv2 is landing. This allows the use of the new experimental FUSE filesystem.")

	// Test flags, not to be used outside tests, ever.
	testOnlyAllowRunAsCurrentUserWithoutChroot = flag.Bool("TESTONLY-unsafe-nonroot", false, "TEST ONLY; do not ever use! This skips many security measures that isolate the host from the sandbox.")
	testOnlyTestNameEnv                        = flag.String("TESTONLY-test-name-env", "", "TEST ONLY; do not ever use! Used for automated tests to improve logging.")
)

func main() {
	// Help and flags commands are generated automatically.
	help := cmd.NewHelp(subcommands.DefaultCommander)
	help.Register(new(cmd.Syscalls))
	subcommands.Register(help, "")
	subcommands.Register(subcommands.FlagsCommand(), "")

	// Installation helpers.
	const helperGroup = "helpers"
	subcommands.Register(new(cmd.Install), helperGroup)
	subcommands.Register(new(cmd.Uninstall), helperGroup)

	// Register user-facing runsc commands.
	subcommands.Register(new(cmd.Checkpoint), "")
	subcommands.Register(new(cmd.Create), "")
	subcommands.Register(new(cmd.Delete), "")
	subcommands.Register(new(cmd.Do), "")
	subcommands.Register(new(cmd.Events), "")
	subcommands.Register(new(cmd.Exec), "")
	subcommands.Register(new(cmd.Gofer), "")
	subcommands.Register(new(cmd.Kill), "")
	subcommands.Register(new(cmd.List), "")
	subcommands.Register(new(cmd.Pause), "")
	subcommands.Register(new(cmd.PS), "")
	subcommands.Register(new(cmd.Restore), "")
	subcommands.Register(new(cmd.Resume), "")
	subcommands.Register(new(cmd.Run), "")
	subcommands.Register(new(cmd.Spec), "")
	subcommands.Register(new(cmd.State), "")
	subcommands.Register(new(cmd.Start), "")
	subcommands.Register(new(cmd.Wait), "")

	// Register internal commands with the internal group name. This causes
	// them to be sorted below the user-facing commands with empty group.
	// The string below will be printed above the commands.
	const internalGroup = "internal use only"
	subcommands.Register(new(cmd.Boot), internalGroup)
	subcommands.Register(new(cmd.Debug), internalGroup)
	subcommands.Register(new(cmd.Gofer), internalGroup)
	subcommands.Register(new(cmd.Statefile), internalGroup)

	// All subcommands must be registered before flag parsing.
	flag.Parse()

	// Are we showing the version?
	if *showVersion {
		// The format here is the same as runc.
		fmt.Fprintf(os.Stdout, "runsc version %s\n", version)
		fmt.Fprintf(os.Stdout, "spec: %s\n", specutils.Version)
		os.Exit(0)
	}

	// TODO(gvisor.dev/issue/193): support systemd cgroups
	if *systemdCgroup {
		fmt.Fprintln(os.Stderr, "systemd cgroup flag passed, but systemd cgroups not supported. See gvisor.dev/issue/193")
		os.Exit(1)
	}

	var errorLogger io.Writer
	if *logFD > -1 {
		errorLogger = os.NewFile(uintptr(*logFD), "error log file")

	} else if *logFilename != "" {
		// We must set O_APPEND and not O_TRUNC because Docker passes
		// the same log file for all commands (and also parses these
		// log files), so we can't destroy them on each command.
		var err error
		errorLogger, err = os.OpenFile(*logFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			cmd.Fatalf("error opening log file %q: %v", *logFilename, err)
		}
	}
	cmd.ErrorLogger = errorLogger

	platformType := *platformName
	if _, err := platform.Lookup(platformType); err != nil {
		cmd.Fatalf("%v", err)
	}

	fsAccess, err := config.MakeFileAccessType(*fileAccess)
	if err != nil {
		cmd.Fatalf("%v", err)
	}

	if fsAccess == config.FileAccessShared && *overlay {
		cmd.Fatalf("overlay flag is incompatible with shared file access")
	}

	netType, err := config.MakeNetworkType(*network)
	if err != nil {
		cmd.Fatalf("%v", err)
	}

	wa, err := config.MakeWatchdogAction(*watchdogAction)
	if err != nil {
		cmd.Fatalf("%v", err)
	}

	if *numNetworkChannels <= 0 {
		cmd.Fatalf("num_network_channels must be > 0, got: %d", *numNetworkChannels)
	}

	refsLeakMode, err := config.MakeRefsLeakMode(*referenceLeakMode)
	if err != nil {
		cmd.Fatalf("%v", err)
	}

	queueingDiscipline, err := config.MakeQueueingDiscipline(*qDisc)
	if err != nil {
		cmd.Fatalf("%s", err)
	}

	// Sets the reference leak check mode. Also set it in config below to
	// propagate it to child processes.
	refs.SetLeakMode(refsLeakMode)

	// Create a new Config from the flags.
	conf := &config.Config{
		RootDir:            *rootDir,
		Debug:              *debug,
		LogFilename:        *logFilename,
		LogFormat:          *logFormat,
		DebugLog:           *debugLog,
		PanicLog:           *panicLog,
		DebugLogFormat:     *debugLogFormat,
		FileAccess:         fsAccess,
		FSGoferHostUDS:     *fsGoferHostUDS,
		Overlay:            *overlay,
		Network:            netType,
		HardwareGSO:        *hardwareGSO,
		SoftwareGSO:        *softwareGSO,
		TXChecksumOffload:  *txChecksumOffload,
		RXChecksumOffload:  *rxChecksumOffload,
		LogPackets:         *logPackets,
		Platform:           platformType,
		Strace:             *strace,
		StraceLogSize:      *straceLogSize,
		WatchdogAction:     wa,
		PanicSignal:        *panicSignal,
		ProfileEnable:      *profile,
		EnableRaw:          *netRaw,
		NumNetworkChannels: *numNetworkChannels,
		Rootless:           *rootless,
		AlsoLogToStderr:    *alsoLogToStderr,
		ReferenceLeakMode:  refsLeakMode,
		OverlayfsStaleRead: *overlayfsStaleRead,
		CPUNumFromQuota:    *cpuNumFromQuota,
		VFS2:               *vfs2Enabled,
		FUSE:               *fuseEnabled,
		QDisc:              queueingDiscipline,
		TestOnlyAllowRunAsCurrentUserWithoutChroot: *testOnlyAllowRunAsCurrentUserWithoutChroot,
		TestOnlyTestNameEnv:                        *testOnlyTestNameEnv,
	}
	if len(*straceSyscalls) != 0 {
		conf.StraceSyscalls = strings.Split(*straceSyscalls, ",")
	}

	// Set up logging.
	if *debug {
		log.SetLevel(log.Debug)
	}

	// Logging will include the local date and time via the time package.
	//
	// On first use, time.Local initializes the local time zone, which
	// involves opening tzdata files on the host. Since this requires
	// opening host files, it must be done before syscall filter
	// installation.
	//
	// Generally there will be a log message before filter installation
	// that will force initialization, but force initialization here in
	// case that does not occur.
	_ = time.Local.String()

	subcommand := flag.CommandLine.Arg(0)

	var e log.Emitter
	if *debugLogFD > -1 {
		f := os.NewFile(uintptr(*debugLogFD), "debug log file")

		e = newEmitter(*debugLogFormat, f)

	} else if *debugLog != "" {
		f, err := specutils.DebugLogFile(*debugLog, subcommand, "" /* name */)
		if err != nil {
			cmd.Fatalf("error opening debug log file in %q: %v", *debugLog, err)
		}
		e = newEmitter(*debugLogFormat, f)

	} else {
		// Stderr is reserved for the application, just discard the logs if no debug
		// log is specified.
		e = newEmitter("text", ioutil.Discard)
	}

	if *panicLogFD > -1 || *debugLogFD > -1 {
		fd := *panicLogFD
		if fd < 0 {
			fd = *debugLogFD
		}
		// Quick sanity check to make sure no other commands get passed
		// a log fd (they should use log dir instead).
		if subcommand != "boot" && subcommand != "gofer" {
			cmd.Fatalf("flags --debug-log-fd and --panic-log-fd should only be passed to 'boot' and 'gofer' command, but was passed to %q", subcommand)
		}

		// If we are the boot process, then we own our stdio FDs and can do what we
		// want with them. Since Docker and Containerd both eat boot's stderr, we
		// dup our stderr to the provided log FD so that panics will appear in the
		// logs, rather than just disappear.
		if err := syscall.Dup3(fd, int(os.Stderr.Fd()), 0); err != nil {
			cmd.Fatalf("error dup'ing fd %d to stderr: %v", fd, err)
		}
	} else if *alsoLogToStderr {
		e = &log.MultiEmitter{e, newEmitter(*debugLogFormat, os.Stderr)}
	}

	log.SetTarget(e)

	log.Infof("***************************")
	log.Infof("Args: %s", os.Args)
	log.Infof("Version %s", version)
	log.Infof("PID: %d", os.Getpid())
	log.Infof("UID: %d, GID: %d", os.Getuid(), os.Getgid())
	log.Infof("Configuration:")
	log.Infof("\t\tRootDir: %s", conf.RootDir)
	log.Infof("\t\tPlatform: %v", conf.Platform)
	log.Infof("\t\tFileAccess: %v, overlay: %t", conf.FileAccess, conf.Overlay)
	log.Infof("\t\tNetwork: %v, logging: %t", conf.Network, conf.LogPackets)
	log.Infof("\t\tStrace: %t, max size: %d, syscalls: %s", conf.Strace, conf.StraceLogSize, conf.StraceSyscalls)
	log.Infof("\t\tVFS2 enabled: %v", conf.VFS2)
	log.Infof("***************************")

	if *testOnlyAllowRunAsCurrentUserWithoutChroot {
		// SIGTERM is sent to all processes if a test exceeds its
		// timeout and this case is handled by syscall_test_runner.
		log.Warningf("Block the TERM signal. This is only safe in tests!")
		signal.Ignore(syscall.SIGTERM)
	}

	// Call the subcommand and pass in the configuration.
	var ws syscall.WaitStatus
	subcmdCode := subcommands.Execute(context.Background(), conf, &ws)
	if subcmdCode == subcommands.ExitSuccess {
		log.Infof("Exiting with status: %v", ws)
		if ws.Signaled() {
			// No good way to return it, emulate what the shell does. Maybe raise
			// signal to self?
			os.Exit(128 + int(ws.Signal()))
		}
		os.Exit(ws.ExitStatus())
	}
	// Return an error that is unlikely to be used by the application.
	log.Warningf("Failure to execute command, err: %v", subcmdCode)
	os.Exit(128)
}

func newEmitter(format string, logFile io.Writer) log.Emitter {
	switch format {
	case "text":
		return log.GoogleEmitter{&log.Writer{Next: logFile}}
	case "json":
		return log.JSONEmitter{&log.Writer{Next: logFile}}
	case "json-k8s":
		return log.K8sJSONEmitter{&log.Writer{Next: logFile}}
	}
	cmd.Fatalf("invalid log format %q, must be 'text', 'json', or 'json-k8s'", format)
	panic("unreachable")
}

func init() {
	// Set default root dir to something (hopefully) user-writeable.
	*rootDir = "/var/run/runsc"
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		*rootDir = filepath.Join(runtimeDir, "runsc")
	}
}
