// Copyright 2022 The gVisor Authors.
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

// list implements subcommands.Command for the "list" command.
type list struct{}

// Name implements subcommands.Command.
func (*list) Name() string {
	return "list"
}

// Synopsis implements subcommands.Command.
func (*list) Synopsis() string {
	return "list all trace sessions"
}

// Usage implements subcommands.Command.
func (*list) Usage() string {
	return `list - list all trace sessions
`
}

// SetFlags implements subcommands.Command.
func (*list) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.
func (l *list) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
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

	sessions, err := c.Sandbox.ListTraceSessions()
	if err != nil {
		util.Fatalf("listing sessions: %v", err)
	}
	fmt.Printf("SESSIONS (%d)\n", len(sessions))
	for _, session := range sessions {
		fmt.Printf("%q\n", session.Name)
		for _, sink := range session.Sinks {
			fmt.Printf("\tSink: %q, dropped: %d\n", sink.Name, sink.Status.DroppedCount)
		}
	}
	return subcommands.ExitSuccess
}
