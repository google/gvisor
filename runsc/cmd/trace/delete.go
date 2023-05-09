// Copyright 2020 The gVisor Authors.
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

package trace

import (
	"context"
	"fmt"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// delete implements subcommands.Command for the "delete" command.
type delete struct {
	sessionName string
}

// Name implements subcommands.Command.
func (*delete) Name() string {
	return "delete"
}

// Synopsis implements subcommands.Command.
func (*delete) Synopsis() string {
	return "delete a trace session"
}

// Usage implements subcommands.Command.
func (*delete) Usage() string {
	return `delete [flags] <sandbox id> - delete a trace session
`
}

// SetFlags implements subcommands.Command.
func (l *delete) SetFlags(f *flag.FlagSet) {
	f.StringVar(&l.sessionName, "name", "", "name of session to be deleted")
}

// Execute implements subcommands.Command.
func (l *delete) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	if len(l.sessionName) == 0 {
		f.Usage()
		return util.Errorf("missing session name, please set --name")
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	opts := container.LoadOpts{
		SkipCheck:     true,
		RootContainer: true,
	}
	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, opts)
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	if err := c.Sandbox.DeleteTraceSession(l.sessionName); err != nil {
		util.Fatalf("deleting session: %v", err)
	}

	fmt.Printf("Trace session %q deleted.\n", l.sessionName)
	return subcommands.ExitSuccess
}
