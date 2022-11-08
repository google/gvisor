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

// ReadControl implements subcommands.Command for the "read-control" command.
type ReadControl struct{}

// Name implements subcommands.Command.Name.
func (*ReadControl) Name() string {
	return "read-control"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*ReadControl) Synopsis() string {
	return "read a cgroups control value inside the container"
}

// Usage implements subcommands.Command.Usage.
func (*ReadControl) Usage() string {
	return `read-control <container-id> <controller> <cgroup-path> <control-value-name>

Where "<container-id>" is the name for the instance of the container,
"<controller>" is the name of an active cgroupv1 controller, <cgroup-path> is
the path to the cgroup to read and <control-value-name> is the name of the
control file to read.

EXAMPLE:
       # runsc read-control <container-id> cpuacct / cpuacct.usage
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *ReadControl) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (r *ReadControl) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() < 4 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	out, err := c.Sandbox.CgroupsReadControlFile(control.CgroupControlFile{
		Controller: f.Arg(1),
		Path:       f.Arg(2),
		Name:       f.Arg(3),
	})
	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return subcommands.ExitFailure
	}
	fmt.Printf("%s\n", out)
	return subcommands.ExitSuccess
}
