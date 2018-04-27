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
	"runtime"
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
	// bundleDir is the path to the bundle directory.
	bundleDir string

	// controllerFD is the file descriptor of a stream socket for the
	// control server that is donated to this process.
	controllerFD int

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
	return `boot [flags]`
}

// SetFlags implements subcommands.Command.SetFlags.
func (b *Boot) SetFlags(f *flag.FlagSet) {
	f.StringVar(&b.bundleDir, "bundle", "", "required path to the root of the bundle directory")
	f.IntVar(&b.controllerFD, "controller-fd", -1, "required FD of a stream socket for the control server that must be donated to this process")
	f.Var(&b.ioFDs, "io-fds", "list of FDs to connect 9P clients. They must follow this order: root first, then mounts as defined in the spec")
	f.BoolVar(&b.console, "console", false, "set to true if the sandbox should allow terminal ioctl(2) syscalls")
	f.BoolVar(&b.applyCaps, "apply-caps", false, "if true, apply capabilities defined in the spec to the process")
}

// Execute implements subcommands.Command.Execute.  It starts a sandbox in a
// waiting state.
func (b *Boot) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if b.bundleDir == "" || b.controllerFD == -1 || f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	// Ensure that if there is a panic, all goroutine stacks are printed.
	debug.SetTraceback("all")

	// Get the spec from the bundleDir.
	spec, err := specutils.ReadSpec(b.bundleDir)
	if err != nil {
		Fatalf("error reading spec: %v", err)
	}
	specutils.LogSpec(spec)

	// Turn any relative paths in the spec to absolute by prepending the bundleDir.
	spec.Root.Path = absPath(b.bundleDir, spec.Root.Path)
	for _, m := range spec.Mounts {
		if m.Source != "" {
			m.Source = absPath(b.bundleDir, m.Source)
		}
	}

	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	if b.applyCaps {
		setCapsAndCallSelf(conf, spec)
		Fatalf("setCapsAndCallSelf must never return")
	}

	// Create the loader.
	s, err := boot.New(spec, conf, b.controllerFD, b.ioFDs.GetArray(), b.console)
	if err != nil {
		Fatalf("error creating loader: %v", err)
	}
	defer s.Destroy()

	// Wait for the start signal from runsc.
	s.WaitForStartSignal()

	// Run the application and wait for it to finish.
	if err := s.Run(); err != nil {
		Fatalf("error running sandbox: %v", err)
	}

	ws := s.WaitExit()
	log.Infof("application exiting with %+v", ws)
	*waitStatus = syscall.WaitStatus(ws.Status())
	return subcommands.ExitSuccess
}

// setCapsAndCallSelf sets capabilities to the current thread and then execve's
// itself again with the same arguments except '--apply-caps' to restart the
// whole process with the desired capabilities.
func setCapsAndCallSelf(conf *boot.Config, spec *specs.Spec) {
	// Keep thread locked while capabilities are changed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := boot.ApplyCaps(conf, spec.Process.Capabilities); err != nil {
		Fatalf("ApplyCaps, err: %v", err)
	}
	binPath, err := specutils.BinPath()
	if err != nil {
		Fatalf("%v", err)
	}

	// Remove --apply-caps arg to call myself.
	var args []string
	for _, arg := range os.Args {
		if !strings.Contains(arg, "apply-caps") {
			args = append(args, arg)
		}
	}

	log.Infof("Execve 'boot' again, bye!")
	log.Infof("%s %v", binPath, args)
	syscall.Exec(binPath, args, []string{})
}
