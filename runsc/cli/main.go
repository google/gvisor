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

// Package cli is the main entrypoint for runsc.
package cli

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.dev/gvisor/runsc/cmd"
	"gvisor.dev/gvisor/runsc/cmd/nvproxy"
	"gvisor.dev/gvisor/runsc/cmd/trace"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/starttime"
	"gvisor.dev/gvisor/runsc/version"
)

// versionFlagName is the name of a flag that triggers printing the version.
// Although this flags is not part of the OCI spec, it is used by
// Docker, and thus should not be removed.
const versionFlagName = "version"

var (
	// These flags are unique to runsc, and are used to configure parts of the
	// system that are not covered by the runtime spec.

	// Debugging flags.
	logFD      = flag.Int("log-fd", -1, "file descriptor to log to.  If set, the 'log' flag is ignored.")
	debugLogFD = flag.Int("debug-log-fd", -1, "file descriptor to write debug logs to.  If set, the 'debug-log-dir' flag is ignored.")
	panicLogFD = flag.Int("panic-log-fd", -1, "file descriptor to write Go's runtime messages.")
	coverageFD = flag.Int("coverage-fd", -1, "file descriptor to write Go coverage output.")
)

// Main is the main entrypoint.
func Main() {
	// Register all commands.
	forEachCmd(subcommands.Register)

	// Register with the main command line.
	config.RegisterFlags(flag.CommandLine)

	// Register version flag if it is not already defined.
	if flag.Lookup(versionFlagName) == nil {
		flag.Bool(versionFlagName, false, "show version and exit.")
	}

	// All subcommands must be registered before flag parsing.
	flag.Parse()

	// Are we showing the version?
	if flag.Get(flag.Lookup(versionFlagName).Value).(bool) {
		// The format here is the same as runc.
		fmt.Fprintf(os.Stdout, "runsc version %s\n", version.Version())
		fmt.Fprintf(os.Stdout, "spec: %s\n", specutils.Version)
		os.Exit(0)
	}

	// Create a new Config from the flags.
	conf, err := config.NewFromFlags(flag.CommandLine)
	if err != nil {
		util.Fatalf(err.Error())
	}

	var errorLogger io.Writer
	if *logFD > -1 {
		errorLogger = os.NewFile(uintptr(*logFD), "error log file")

	} else if conf.LogFilename != "" {
		// We must set O_APPEND and not O_TRUNC because Docker passes
		// the same log file for all commands (and also parses these
		// log files), so we can't destroy them on each command.
		var err error
		errorLogger, err = os.OpenFile(conf.LogFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			util.Fatalf("error opening log file %q: %v", conf.LogFilename, err)
		}
	}
	util.ErrorLogger = errorLogger

	if _, err := platform.Lookup(conf.Platform); err != nil {
		util.Fatalf("%v", err)
	}

	// Sets the reference leak check mode. Also set it in config below to
	// propagate it to child processes.
	refs.SetLeakMode(conf.ReferenceLeak)

	subcommand := flag.CommandLine.Arg(0)

	// Set up logging.
	if conf.Debug && specutils.IsDebugCommand(conf, subcommand) {
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

	// Set the start time as soon as possible.
	startTime := starttime.Get()

	var emitters log.MultiEmitter
	if *debugLogFD > -1 {
		f := os.NewFile(uintptr(*debugLogFD), "debug log file")

		emitters = append(emitters, newEmitter(conf.DebugLogFormat, f))

	} else if len(conf.DebugLog) > 0 && specutils.IsDebugCommand(conf, subcommand) {
		f, err := specutils.DebugLogFile(conf.DebugLog, subcommand, "" /* name */, startTime)
		if err != nil {
			util.Fatalf("error opening debug log file in %q: %v", conf.DebugLog, err)
		}
		emitters = append(emitters, newEmitter(conf.DebugLogFormat, f))

	} else {
		// Stderr is reserved for the application, just discard the logs if no debug
		// log is specified.
		emitters = append(emitters, newEmitter("text", ioutil.Discard))
	}

	if *panicLogFD > -1 || *debugLogFD > -1 {
		fd := *panicLogFD
		if fd < 0 {
			fd = *debugLogFD
		}
		// Quick sanity check to make sure no other commands get passed
		// a log fd (they should use log dir instead).
		if subcommand != "boot" && subcommand != "gofer" {
			util.Fatalf("flags --debug-log-fd and --panic-log-fd should only be passed to 'boot' and 'gofer' command, but was passed to %q", subcommand)
		}

		// If we are the boot process, then we own our stdio FDs and can do what we
		// want with them. Since Docker and Containerd both eat boot's stderr, we
		// dup our stderr to the provided log FD so that panics will appear in the
		// logs, rather than just disappear.
		if err := unix.Dup3(fd, int(os.Stderr.Fd()), 0); err != nil {
			util.Fatalf("error dup'ing fd %d to stderr: %v", fd, err)
		}
	} else if conf.AlsoLogToStderr {
		emitters = append(emitters, newEmitter(conf.DebugLogFormat, os.Stderr))
	}
	if ulEmittter, add := userLogEmitter(conf, subcommand); add {
		emitters = append(emitters, ulEmittter)
	}

	switch len(emitters) {
	case 0:
		// Do nothing.
	case 1:
		// Use the singular emitter to avoid needless
		// `for` loop overhead when logging to a single place.
		log.SetTarget(emitters[0])
	default:
		log.SetTarget(&emitters)
	}

	const delimString = `**************** gVisor ****************`
	log.Infof(delimString)
	log.Infof("Version %s, %s, %s, %d CPUs, %s, PID %d, PPID %d, UID %d, GID %d", version.Version(), runtime.Version(), runtime.GOARCH, runtime.NumCPU(), runtime.GOOS, os.Getpid(), os.Getppid(), os.Getuid(), os.Getgid())
	log.Debugf("Page size: 0x%x (%d bytes)", os.Getpagesize(), os.Getpagesize())
	log.Infof("Args: %v", os.Args)
	conf.Log()
	log.Infof(delimString)

	if *coverageFD >= 0 {
		f := os.NewFile(uintptr(*coverageFD), "coverage file")
		coverage.EnableReport(f)
	}
	if conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		// SIGTERM is sent to all processes if a test exceeds its
		// timeout and this case is handled by syscall_test_runner.
		log.Warningf("Block the TERM signal. This is only safe in tests!")
		signal.Ignore(unix.SIGTERM)
	}
	linux.SetAFSSyscallPanic(conf.TestOnlyAFSSyscallPanic)

	// Call the subcommand and pass in the configuration.
	var ws unix.WaitStatus
	subcmdCode := subcommands.Execute(context.Background(), conf, &ws)
	// Check for leaks and write coverage report before os.Exit().
	refs.DoLeakCheck()
	_ = coverage.Report()
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

// forEachCmd invokes the passed callback for each command supported by runsc.
func forEachCmd(cb func(cmd subcommands.Command, group string)) {
	// Help and flags commands are generated automatically.
	help := cmd.NewHelp(subcommands.DefaultCommander)
	help.Register(new(cmd.Platforms))
	help.Register(new(cmd.Syscalls))
	cb(help, "")
	cb(subcommands.FlagsCommand(), "")

	// Register OCI user-facing runsc commands.
	cb(new(cmd.Checkpoint), "")
	cb(new(cmd.Create), "")
	cb(new(cmd.Delete), "")
	cb(new(cmd.Do), "")
	cb(new(cmd.Events), "")
	cb(new(cmd.Exec), "")
	cb(new(cmd.Kill), "")
	cb(new(cmd.List), "")
	cb(new(cmd.PS), "")
	cb(new(cmd.Pause), "")
	cb(new(cmd.PortForward), "")
	cb(new(cmd.Restore), "")
	cb(new(cmd.Resume), "")
	cb(new(cmd.Run), "")
	cb(new(cmd.Spec), "")
	cb(new(cmd.Start), "")
	cb(new(cmd.State), "")
	cb(new(cmd.Wait), "")

	// Helpers.
	const helperGroup = "helpers"
	cb(new(cmd.Install), helperGroup)
	cb(new(cmd.Mitigate), helperGroup)
	cb(new(cmd.Uninstall), helperGroup)
	cb(new(nvproxy.Nvproxy), helperGroup)
	cb(new(trace.Trace), helperGroup)

	const debugGroup = "debug"
	cb(new(cmd.Debug), debugGroup)
	cb(new(cmd.Statefile), debugGroup)
	cb(new(cmd.Symbolize), debugGroup)
	cb(new(cmd.Usage), debugGroup)
	cb(new(cmd.ReadControl), debugGroup)
	cb(new(cmd.WriteControl), debugGroup)

	const metricGroup = "metrics"
	cb(new(cmd.MetricMetadata), metricGroup)
	cb(new(cmd.MetricExport), metricGroup)
	cb(new(cmd.MetricServer), metricGroup)

	// Internal commands.
	const internalGroup = "internal use only"
	cb(new(cmd.Boot), internalGroup)
	cb(new(cmd.Gofer), internalGroup)
	cb(new(cmd.Umount), internalGroup)
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
	util.Fatalf("invalid log format %q, must be 'text', 'json', or 'json-k8s'", format)
	panic("unreachable")
}

// userLogEmitter returns an emitter to add logs to user logs if requested.
func userLogEmitter(conf *config.Config, subcommand string) (log.Emitter, bool) {
	if subcommand != "boot" || !conf.DebugToUserLog {
		return nil, false
	}
	// We need to manually scan for `--user-log-fd` since it is a flag of the
	// `boot` subcommand. We know it is in `--user-log-fd=FD` format because
	// we control how arguments to `runsc boot` are formatted.
	const userLogFDFlagPrefix = "--user-log-fd="
	var userLog *os.File
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, userLogFDFlagPrefix) {
			continue
		}
		if userLog != nil {
			util.Fatalf("duplicate %q flag", userLogFDFlagPrefix)
		}
		userLogFD, err := strconv.Atoi(arg[len(userLogFDFlagPrefix):])
		if err != nil {
			util.Fatalf("invalid user log FD flag %q: %v", arg, err)
		}
		userLog = os.NewFile(uintptr(userLogFD), "user log file")
	}
	if userLog == nil {
		return nil, false
	}
	return log.K8sJSONEmitter{&log.Writer{Next: userLog}}, true
}
