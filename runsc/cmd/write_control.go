// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// WriteControl implements subcommands.Command for the "write-control" command.
type WriteControl struct{}

// Name implements subcommands.Command.Name.
func (*WriteControl) Name() string {
	return "write-control"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*WriteControl) Synopsis() string {
	return "write a cgroups control value inside the container"
}

// Usage implements subcommands.Command.Usage.
func (*WriteControl) Usage() string {
	return `write-control <container-id> <controller> <cgroup-path> <control-value-name> <data-to-write>

Where "<container-id>" is the name for the instance of the container,
"<controller>" is the name of an active cgroupv1 controller, <cgroup-path> is
the path to the cgroup to write and <control-value-name> is the name of the
control file to write.

EXAMPLE:
       # runsc write-control <container-id> memory / memory.limit_in_bytes 536870912
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *WriteControl) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (r *WriteControl) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() < 5 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	err = c.Sandbox.CgroupsWriteControlFile(control.CgroupControlFile{
		Controller: f.Arg(1),
		Path:       f.Arg(2),
		Name:       f.Arg(3),
	}, f.Arg(4))
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
