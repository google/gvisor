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

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Create implements subcommands.Command for the "create" command.
type Create struct {
	// bundleDir is the path to the bundle directory (defaults to the
	// current working directory).
	bundleDir string

	// pidFile is the filename that the sandbox pid will be written to.
	// This file should only be created once the container process inside
	// the sandbox is ready to use.
	pidFile string

	// consoleSocket is the path to an AF_UNIX socket which will receive a
	// file descriptor referencing the master end of the console's
	// pseudoterminal.  This is ignored unless spec.Process.Terminal is
	// true.
	consoleSocket string

	// userLog is the path to send user-visible logs to. This log is different
	// from debug logs. The former is meant to be consumed by the users and should
	// contain only information that is relevant to the person running the
	// container, e.g. unsuported syscalls, while the later is more verbose and
	// consumed by developers.
	userLog string
}

// Name implements subcommands.Command.Name.
func (*Create) Name() string {
	return "create"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Create) Synopsis() string {
	return "create a secure container"
}

// Usage implements subcommands.Command.Usage.
func (*Create) Usage() string {
	return `create [flags] <container id> - create a secure container
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Create) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.bundleDir, "bundle", "", "path to the root of the bundle directory, defaults to the current directory")
	f.StringVar(&c.consoleSocket, "console-socket", "", "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal")
	f.StringVar(&c.pidFile, "pid-file", "", "filename that the container pid will be written to")
	f.StringVar(&c.userLog, "user-log", "", "filename to send user-visible logs to. Empty means no logging.")
}

// Execute implements subcommands.Command.Execute.
func (c *Create) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	if conf.Rootless {
		return util.Errorf("Rootless mode not supported with %q", c.Name())
	}

	bundleDir := c.bundleDir
	if bundleDir == "" {
		bundleDir = getwdOrDie()
	}
	spec, err := specutils.ReadSpec(bundleDir, conf)
	if err != nil {
		return util.Errorf("reading spec: %v", err)
	}
	specutils.LogSpec(spec)

	// Create the container. A new sandbox will be created for the
	// container unless the metadata specifies that it should be run in an
	// existing container.
	contArgs := container.Args{
		ID:            id,
		Spec:          spec,
		BundleDir:     bundleDir,
		ConsoleSocket: c.consoleSocket,
		PIDFile:       c.pidFile,
		UserLog:       c.userLog,
	}
	if _, err := container.New(conf, contArgs); err != nil {
		return util.Errorf("creating container: %v", err)
	}
	return subcommands.ExitSuccess
}
