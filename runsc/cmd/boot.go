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

package cmd

import (
	"os"
	"runtime/debug"
	"strings"
	"syscall"

	"context"
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

	// console is set to true if the sandbox should allow terminal ioctl(2)
	// syscalls.
	console bool

	// applyCaps determines if capabilities defined in the spec should be applied
	// to the process.
	applyCaps bool
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
	f.BoolVar(&b.console, "console", false, "set to true if the sandbox should allow terminal ioctl(2) syscalls")
	f.BoolVar(&b.applyCaps, "apply-caps", false, "if true, apply capabilities defined in the spec to the process")
}

// Execute implements subcommands.Command.Execute.  It starts a sandbox in a
// waiting state.
func (b *Boot) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if b.specFD == -1 || b.controllerFD == -1 || f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	// Ensure that if there is a panic, all goroutine stacks are printed.
	debug.SetTraceback("all")

	// Get the spec from the specFD.
	specFile := os.NewFile(uintptr(b.specFD), "spec file")
	defer specFile.Close()
	spec, err := specutils.ReadSpecFromFile(b.bundleDir, specFile)
	if err != nil {
		Fatalf("error reading spec: %v", err)
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
			if !strings.Contains(arg, "apply-caps") {
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
	l, err := boot.New(f.Arg(0), spec, conf, b.controllerFD, b.deviceFD, b.ioFDs.GetArray(), b.console)
	if err != nil {
		Fatalf("error creating loader: %v", err)
	}

	// Notify other processes the loader has been created.
	l.NotifyLoaderCreated()

	// Wait for the start signal from runsc.
	l.WaitForStartSignal()

	// Run the application and wait for it to finish.
	if err := l.Run(); err != nil {
		l.Destroy()
		Fatalf("error running sandbox: %v", err)
	}

	ws := l.WaitExit()
	log.Infof("application exiting with %+v", ws)
	*waitStatus = syscall.WaitStatus(ws.Status())
	l.Destroy()
	return subcommands.ExitSuccess
}
