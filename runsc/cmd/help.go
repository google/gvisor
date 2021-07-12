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
	"fmt"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

// NewHelp returns a help command for the given commander.
func NewHelp(cdr *subcommands.Commander) *Help {
	return &Help{
		cdr: cdr,
	}
}

// Help implements subcommands.Command for the "help" command. The 'help'
// command prints help for commands registered to a Commander but also allows for
// registering additional help commands that print other documentation.
type Help struct {
	cdr      *subcommands.Commander
	commands []subcommands.Command
	help     bool
}

// Name implements subcommands.Command.Name.
func (*Help) Name() string {
	return "help"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Help) Synopsis() string {
	return "Print help documentation."
}

// Usage implements subcommands.Command.Usage.
func (*Help) Usage() string {
	return `help [<subcommand>]:
	With an argument, prints detailed information on the use of
	the specified topic or subcommand. With no argument, print a list of
	all commands and a brief description of each.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (h *Help) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (h *Help) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	switch f.NArg() {
	case 0:
		fmt.Fprintf(h.cdr.Output, "Usage: %s <flags> <subcommand> <subcommand args>\n\n", h.cdr.Name())
		fmt.Fprintf(h.cdr.Output, `runsc is the gVisor container runtime.

Functionality is provided by subcommands. For help with a specific subcommand,
use "%s %s <subcommand>".

`, h.cdr.Name(), h.Name())
		h.cdr.VisitGroups(func(g *subcommands.CommandGroup) {
			h.cdr.ExplainGroup(h.cdr.Output, g)
		})

		fmt.Fprintf(h.cdr.Output, "Additional help topics (Use \"%s %s <topic>\" to see help on the topic):\n", h.cdr.Name(), h.Name())
		for _, cmd := range h.commands {
			fmt.Fprintf(h.cdr.Output, "\t%-15s  %s\n", cmd.Name(), cmd.Synopsis())
		}
		fmt.Fprintf(h.cdr.Output, "\nUse \"%s flags\" for a list of top-level flags\n", h.cdr.Name())
		return subcommands.ExitSuccess
	default:
		// Look for commands registered to the commander and print help explanation if found.
		found := false
		h.cdr.VisitCommands(func(g *subcommands.CommandGroup, cmd subcommands.Command) {
			if f.Arg(0) == cmd.Name() {
				h.cdr.ExplainCommand(h.cdr.Output, cmd)
				found = true
			}
		})
		if found {
			return subcommands.ExitSuccess
		}

		// Next check commands registered to the help command.
		for _, cmd := range h.commands {
			if f.Arg(0) == cmd.Name() {
				fs := flag.NewFlagSet(f.Arg(0), flag.ContinueOnError)
				fs.Usage = func() { h.cdr.ExplainCommand(h.cdr.Error, cmd) }
				cmd.SetFlags(fs)
				if fs.Parse(f.Args()[1:]) != nil {
					return subcommands.ExitUsageError
				}
				return cmd.Execute(ctx, f, args...)
			}
		}

		fmt.Fprintf(h.cdr.Error, "Subcommand %s not understood\n", f.Arg(0))
	}

	f.Usage()
	return subcommands.ExitUsageError
}

// Register registers a new help command.
func (h *Help) Register(cmd subcommands.Command) {
	h.commands = append(h.commands, cmd)
}
