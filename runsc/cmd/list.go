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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// List implements subcommands.Command for the "list" command.
type List struct {
	quiet   bool
	format  string
	sandbox bool
}

// Name implements subcommands.command.name.
func (*List) Name() string {
	return "list"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*List) Synopsis() string {
	return "list containers started by runsc with the given root"
}

// Usage implements subcommands.Command.Usage.
func (*List) Usage() string {
	return `list [flags]`
}

// SetFlags implements subcommands.Command.SetFlags.
func (l *List) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&l.quiet, "quiet", false, "only list container ids")
	f.StringVar(&l.format, "format", "text", "output format: 'text' (default) or 'json'")
	f.BoolVar(&l.sandbox, "sandbox", false, "limit output to sandboxes only")
}

// Execute implements subcommands.Command.Execute.
func (l *List) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	if err := l.execute(conf.RootDir, os.Stdout); err != nil {
		util.Fatalf("%v", err)
	}
	return subcommands.ExitSuccess
}

func (l *List) execute(rootDir string, out io.Writer) error {
	ids, err := container.List(rootDir)
	if err != nil {
		return err
	}

	if l.sandbox {
		sandboxes := make(map[string]struct{})
		for _, id := range ids {
			sandboxes[id.SandboxID] = struct{}{}
		}
		// Reset ids to list only sandboxes.
		ids = nil
		for id := range sandboxes {
			ids = append(ids, container.FullID{SandboxID: id, ContainerID: id})
		}
	}

	if l.quiet {
		for _, id := range ids {
			fmt.Fprintln(out, id.ContainerID)
		}
		return nil
	}

	// Collect the containers.
	var containers []*container.Container
	for _, id := range ids {
		c, err := container.Load(rootDir, id, container.LoadOpts{Exact: true})
		if err != nil {
			log.Warningf("Skipping container %q: %v", id, err)
			continue
		}
		containers = append(containers, c)
	}

	switch l.format {
	case "text":
		// Print a nice table.
		w := tabwriter.NewWriter(out, 12, 1, 3, ' ', 0)
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
		_ = w.Flush()
	case "json":
		// Print just the states.
		var states []specs.State
		for _, c := range containers {
			states = append(states, c.State())
		}
		if err := json.NewEncoder(out).Encode(states); err != nil {
			return fmt.Errorf("marshaling container state: %w", err)
		}
	default:
		return fmt.Errorf("unknown list format %q", l.format)
	}
	return nil
}
