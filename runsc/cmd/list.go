// Copyright 2018 Google Inc.
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
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"context"
	"flag"
	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

// List implements subcommands.Command for the "list" command for the "list" command.
type List struct {
	quiet  bool
	format string
}

// Name implements subcommands.command.name.
func (*List) Name() string {
	return "list"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*List) Synopsis() string {
	return "list contaners started by runsc with the given root"
}

// Usage implements subcommands.Command.Usage.
func (*List) Usage() string {
	return `list [flags]`
}

// SetFlags implements subcommands.Command.SetFlags.
func (l *List) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&l.quiet, "quiet", false, "only list container ids")
	f.StringVar(&l.format, "format", "text", "output format: 'text' (default) or 'json'")
}

// Execute implements subcommands.Command.Execute.
func (l *List) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*boot.Config)
	ids, err := container.List(conf.RootDir)
	if err != nil {
		Fatalf("%v", err)
	}

	if l.quiet {
		for _, id := range ids {
			fmt.Println(id)
		}
		return subcommands.ExitSuccess
	}

	// Collect the containers.
	var containers []*container.Container
	for _, id := range ids {
		c, err := container.Load(conf.RootDir, id)
		if err != nil {
			Fatalf("error loading container %q: %v", id, err)
		}
		containers = append(containers, c)
	}

	switch l.format {
	case "text":
		// Print a nice table.
		w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
		fmt.Fprint(w, "ID\tPID\tSTATUS\tBUNDLE\tCREATED\tOWNER\n")
		for _, c := range containers {
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
				c.ID,
				c.SandboxPid(),
				c.Status,
				c.BundleDir,
				c.CreatedAt.Format(time.RFC3339Nano),
				c.Owner)
		}
		w.Flush()
	case "json":
		// Print just the states.
		var states []specs.State
		for _, c := range containers {
			states = append(states, c.State())
		}
		if err := json.NewEncoder(os.Stdout).Encode(states); err != nil {
			Fatalf("error marshaling container state: %v", err)
		}
	default:
		Fatalf("unknown list format %q", l.format)
	}
	return subcommands.ExitSuccess
}
