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
	"syscall"

	"context"
	"flag"
	"github.com/google/subcommands"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// Run implements subcommands.Command for the "run" command.
type Run struct {
	// Run flags are a super-set of those for Create.
	Create
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
	r.Create.SetFlags(f)
}

// Execute implements subcommands.Command.Execute.
func (r *Run) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*boot.Config)
	waitStatus := args[1].(*syscall.WaitStatus)

	bundleDir := r.bundleDir
	if bundleDir == "" {
		bundleDir = getwdOrDie()
	}
	spec, err := specutils.ReadSpec(bundleDir)
	if err != nil {
		Fatalf("error reading spec: %v", err)
	}
	specutils.LogSpec(spec)

	ws, err := container.Run(id, spec, conf, bundleDir, r.consoleSocket, r.pidFile, r.userLog)
	if err != nil {
		Fatalf("error running container: %v", err)
	}

	*waitStatus = ws
	return subcommands.ExitSuccess
}
