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
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Pause implements subcommands.Command for the "pause" command.
type Pause struct{}

// Name implements subcommands.Command.Name.
func (*Pause) Name() string {
	return "pause"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Pause) Synopsis() string {
	return "pause suspends all processes in a container"
}

// Usage implements subcommands.Command.Usage.
func (*Pause) Usage() string {
	return `pause <container id> - pause process in instance of container.`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*Pause) SetFlags(f *flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (*Pause) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		Fatalf("loading container: %v", err)
	}

	if err := cont.Pause(); err != nil {
		Fatalf("pause failed: %v", err)
	}

	return subcommands.ExitSuccess
}
