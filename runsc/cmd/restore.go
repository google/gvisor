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
	"path/filepath"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Restore implements subcommands.Command for the "restore" command.
type Restore struct {
	// Restore flags are a super-set of those for Create.
	Create

	// imagePath is the path to the saved container image
	imagePath string

	// detach indicates that runsc has to start a process and exit without waiting it.
	detach bool
}

// Name implements subcommands.Command.Name.
func (*Restore) Name() string {
	return "restore"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Restore) Synopsis() string {
	return "restore a saved state of container (experimental)"
}

// Usage implements subcommands.Command.Usage.
func (*Restore) Usage() string {
	return `restore [flags] <container id> - restore saved state of container.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Restore) SetFlags(f *flag.FlagSet) {
	r.Create.SetFlags(f)
	f.StringVar(&r.imagePath, "image-path", "", "directory path to saved container image")
	f.BoolVar(&r.detach, "detach", false, "detach from the container's process")

	// Unimplemented flags necessary for compatibility with docker.

	var nsr bool
	f.BoolVar(&nsr, "no-subreaper", false, "ignored")

	var wp string
	f.StringVar(&wp, "work-path", "", "ignored")
}

// Execute implements subcommands.Command.Execute.
func (r *Restore) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	if conf.Rootless {
		return util.Errorf("Rootless mode not supported with %q", r.Name())
	}

	bundleDir := r.bundleDir
	if bundleDir == "" {
		bundleDir = getwdOrDie()
	}
	spec, err := specutils.ReadSpec(bundleDir, conf)
	if err != nil {
		return util.Errorf("reading spec: %v", err)
	}
	specutils.LogSpec(spec)

	if r.imagePath == "" {
		return util.Errorf("image-path flag must be provided")
	}

	conf.RestoreFile = filepath.Join(r.imagePath, checkpointFileName)

	runArgs := container.Args{
		ID:            id,
		Spec:          spec,
		BundleDir:     bundleDir,
		ConsoleSocket: r.consoleSocket,
		PIDFile:       r.pidFile,
		UserLog:       r.userLog,
		Attached:      !r.detach,
	}
	ws, err := container.Run(conf, runArgs)
	if err != nil {
		return util.Errorf("running container: %v", err)
	}
	*waitStatus = ws

	return subcommands.ExitSuccess
}
