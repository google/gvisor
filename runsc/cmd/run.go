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

package cmd

import (
	"context"
	"os"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Run implements subcommands.Command for the "run" command.
type Run struct {
	// Run flags are a super-set of those for Create.
	Create

	// detach indicates that runsc has to start a process and exit without waiting it.
	detach bool

	// passFDs are user-supplied FDs from the host to be exposed to the
	// sandboxed app.
	passFDs fdMappings

	// execFD is the host file descriptor used for program execution.
	execFD int
}

// Name implements subcommands.Command.Name.
func (*Run) Name() string {
	return "run"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Run) Synopsis() string {
	return "create and run a secure container"
}

// Usage implements subcommands.Command.Usage.
func (*Run) Usage() string {
	return `run [flags] <container id> - create and run a secure container.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Run) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&r.detach, "detach", false, "detach from the container's process")
	f.Var(&r.passFDs, "pass-fd", "file descriptor passed to the container in M:N format, where M is the host and N is the guest descriptor (can be supplied multiple times)")
	f.IntVar(&r.execFD, "exec-fd", -1, "host file descriptor used for program execution")
	r.Create.SetFlags(f)
}

// Execute implements subcommands.Command.Execute.
func (r *Run) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	if conf.Rootless {
		if conf.Network == config.NetworkSandbox {
			return util.Errorf("sandbox network isn't supported with --rootless, use --network=none or --network=host")
		}

		if err := specutils.MaybeRunAsRoot(); err != nil {
			return util.Errorf("Error executing inside namespace: %v", err)
		}
		// Execution will continue here if no more capabilities are needed...
	}

	bundleDir := r.bundleDir
	if bundleDir == "" {
		bundleDir = getwdOrDie()
	}
	spec, err := specutils.ReadSpec(bundleDir, conf)
	if err != nil {
		return util.Errorf("reading spec: %v", err)
	}
	specutils.LogSpecDebug(spec, conf.OCISeccomp)

	// Create files from file descriptors.
	fdMap := make(map[int]*os.File)
	for _, mapping := range r.passFDs {
		file := os.NewFile(uintptr(mapping.Host), "")
		if file == nil {
			return util.Errorf("Failed to create file from file descriptor %d", mapping.Host)
		}
		fdMap[mapping.Guest] = file
	}

	var execFile *os.File
	if r.execFD >= 0 {
		execFile = os.NewFile(uintptr(r.execFD), "exec-fd")
	}

	// Close the underlying file descriptors after we have passed them.
	defer func() {
		for _, file := range fdMap {
			fd := file.Fd()
			if file.Close() != nil {
				log.Debugf("Failed to close FD %d", fd)
			}
		}

		if execFile != nil && execFile.Close() != nil {
			log.Debugf("Failed to close exec FD")
		}
	}()

	runArgs := container.Args{
		ID:            id,
		Spec:          spec,
		BundleDir:     bundleDir,
		ConsoleSocket: r.consoleSocket,
		PIDFile:       r.pidFile,
		UserLog:       r.userLog,
		Attached:      !r.detach,
		PassFiles:     fdMap,
		ExecFile:      execFile,
	}
	ws, err := container.Run(conf, runArgs)
	if err != nil {
		return util.Errorf("running container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}
