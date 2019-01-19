// Copyright 2018 Google LLC
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

package cmd

import (
	"context"
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Boot implements subcommands.Command for the "boot" command which starts a
// new sandbox. It should not be called directly.
type Boot struct {
	// bundleDir is the directory containing the OCI spec.
	bundleDir string

	// specFD is the file descriptor that the spec will be read from.
	specFD int

	// controllerFD is the file descriptor of a stream socket for the
	// control server that is donated to this process.
	controllerFD int

	// deviceFD is the file descriptor for the platform device file.
	deviceFD int

	// ioFDs is the list of FDs used to connect to FS gofers.
	ioFDs intFlags

	// stdioFDs are the fds for stdin, stdout, and stderr. They must be
	// provided in that order.
	stdioFDs intFlags

	// console is set to true if the sandbox should allow terminal ioctl(2)
	// syscalls.
	console bool

	// applyCaps determines if capabilities defined in the spec should be applied
	// to the process.
	applyCaps bool

	// setUpChroot is set to true if the sandbox is started in an empty root.
	setUpRoot bool

	// cpuNum number of CPUs to create inside the sandbox.
	cpuNum int

	// totalMem sets the initial amount of total memory to report back to the
	// container.
	totalMem uint64

	// userLogFD is the file descriptor to write user logs to.
	userLogFD int

	// startSyncFD is the file descriptor to synchronize runsc and sandbox.
	startSyncFD int

	// pidns is set if the sanadbox is in its own pid namespace.
	pidns bool
}

// Name implements subcommands.Command.Name.
func (*Boot) Name() string {
	return "boot"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Boot) Synopsis() string {
	return "launch a sandbox process (internal use only)"
}

// Usage implements subcommands.Command.Usage.
func (*Boot) Usage() string {
	return `boot [flags] <container id>`
}

// SetFlags implements subcommands.Command.SetFlags.
func (b *Boot) SetFlags(f *flag.FlagSet) {
	f.StringVar(&b.bundleDir, "bundle", "", "required path to the root of the bundle directory")
	f.IntVar(&b.specFD, "spec-fd", -1, "required fd with the container spec")
	f.IntVar(&b.controllerFD, "controller-fd", -1, "required FD of a stream socket for the control server that must be donated to this process")
	f.IntVar(&b.deviceFD, "device-fd", -1, "FD for the platform device file")
	f.Var(&b.ioFDs, "io-fds", "list of FDs to connect 9P clients. They must follow this order: root first, then mounts as defined in the spec")
	f.Var(&b.stdioFDs, "stdio-fds", "list of FDs containing sandbox stdin, stdout, and stderr in that order")
	f.BoolVar(&b.console, "console", false, "set to true if the sandbox should allow terminal ioctl(2) syscalls")
	f.BoolVar(&b.applyCaps, "apply-caps", false, "if true, apply capabilities defined in the spec to the process")
	f.BoolVar(&b.setUpRoot, "setup-root", false, "if true, set up an empty root for the process")
	f.BoolVar(&b.pidns, "pidns", false, "if true, the sandbox is in its own PID namespace")
	f.IntVar(&b.cpuNum, "cpu-num", 0, "number of CPUs to create inside the sandbox")
	f.Uint64Var(&b.totalMem, "total-memory", 0, "sets the initial amount of total memory to report back to the container")
	f.IntVar(&b.userLogFD, "user-log-fd", 0, "file descriptor to write user logs to. 0 means no logging.")
	f.IntVar(&b.startSyncFD, "start-sync-fd", -1, "required FD to used to synchronize sandbox startup")
}

// Execute implements subcommands.Command.Execute.  It starts a sandbox in a
// waiting state.
func (b *Boot) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if b.specFD == -1 || b.controllerFD == -1 || b.startSyncFD == -1 || f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	// Ensure that if there is a panic, all goroutine stacks are printed.
	debug.SetTraceback("all")

	if b.setUpRoot {
		if err := setUpChroot(b.pidns); err != nil {
			Fatalf("error setting up chroot: %v", err)
		}

		specutils.ExePath = "/runsc"
		if !b.applyCaps {
			// Remove --setup-root arg to call myself.
			var args []string
			for _, arg := range os.Args {
				if !strings.Contains(arg, "setup-root") {
					args = append(args, arg)
				}
			}
			// Note that we've already read the spec from the spec FD, and
			// we will read it again after the exec call. This works
			// because the ReadSpecFromFile function seeks to the beginning
			// of the file before reading.
			if err := callSelfAsNobody(args); err != nil {
				Fatalf("%v", err)
			}
			panic("callSelfAsNobody must never return success")
		}
	}

	// Get the spec from the specFD.
	specFile := os.NewFile(uintptr(b.specFD), "spec file")
	defer specFile.Close()
	spec, err := specutils.ReadSpecFromFile(b.bundleDir, specFile)
	if err != nil {
		Fatalf("reading spec: %v", err)
	}
	specutils.LogSpec(spec)

	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	if b.applyCaps {
		caps := spec.Process.Capabilities
		if caps == nil {
			caps = &specs.LinuxCapabilities{}
		}
		if conf.Platform == boot.PlatformPtrace {
			// Ptrace platform requires extra capabilities.
			const c = "CAP_SYS_PTRACE"
			caps.Bounding = append(caps.Bounding, c)
			caps.Effective = append(caps.Effective, c)
			caps.Permitted = append(caps.Permitted, c)
		}

		// Remove --apply-caps arg to call myself.
		var args []string
		for _, arg := range os.Args {
			if !strings.Contains(arg, "setup-root") && !strings.Contains(arg, "apply-caps") {
				args = append(args, arg)
			}
		}

		// Note that we've already read the spec from the spec FD, and
		// we will read it again after the exec call. This works
		// because the ReadSpecFromFile function seeks to the beginning
		// of the file before reading.
		if err := setCapsAndCallSelf(args, caps); err != nil {
			Fatalf("%v", err)
		}
		panic("setCapsAndCallSelf must never return success")
	}

	// Create the loader.
	bootArgs := boot.Args{
		ID:           f.Arg(0),
		Spec:         spec,
		Conf:         conf,
		ControllerFD: b.controllerFD,
		DeviceFD:     b.deviceFD,
		GoferFDs:     b.ioFDs.GetArray(),
		StdioFDs:     b.stdioFDs.GetArray(),
		Console:      b.console,
		NumCPU:       b.cpuNum,
		TotalMem:     b.totalMem,
		UserLogFD:    b.userLogFD,
	}
	l, err := boot.New(bootArgs)
	if err != nil {
		Fatalf("creating loader: %v", err)
	}

	// Fatalf exits the process and doesn't run defers.
	// 'l' must be destroyed explicitly after this point!

	// Notify the parent process the sandbox has booted (and that the controller
	// is up).
	startSyncFile := os.NewFile(uintptr(b.startSyncFD), "start-sync file")
	buf := make([]byte, 1)
	if w, err := startSyncFile.Write(buf); err != nil || w != 1 {
		l.Destroy()
		Fatalf("unable to write into the start-sync descriptor: %v", err)
	}
	// Closes startSyncFile because 'l.Run()' only returns when the sandbox exits.
	startSyncFile.Close()

	// Wait for the start signal from runsc.
	l.WaitForStartSignal()

	// Run the application and wait for it to finish.
	if err := l.Run(); err != nil {
		l.Destroy()
		Fatalf("running sandbox: %v", err)
	}

	ws := l.WaitExit()
	log.Infof("application exiting with %+v", ws)
	*waitStatus = syscall.WaitStatus(ws.Status())
	l.Destroy()
	return subcommands.ExitSuccess
}
