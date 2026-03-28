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
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// PS implements subcommands.Command for the "ps" command.
type PS struct {
	containerLoader
	format string
}

// Name implements subcommands.Command.Name.
func (*PS) Name() string {
	return "ps"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*PS) Synopsis() string {
	return "ps displays the processes running inside a container"
}

// Usage implements subcommands.Command.Usage.
func (*PS) Usage() string {
	return "<container-id> [ps options]"
}

// SetFlags implements subcommands.Command.SetFlags.
func (ps *PS) SetFlags(f *flag.FlagSet) {
	f.StringVar(&ps.format, "format", "table", "output format. Select one of: table or json (default: table)")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (ps *PS) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := ps.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (ps *PS) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	c, err := ps.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}
	pList, err := c.Processes()
	if err != nil {
		util.Fatalf("getting processes for container: %v", err)
	}

	switch ps.format {
	case "table":
		fmt.Println(control.ProcessListToTable(pList))
	case "json":
		o, err := control.PrintPIDsJSON(pList)
		if err != nil {
			util.Fatalf("generating JSON: %v", err)
		}
		fmt.Println(o)
	default:
		util.Fatalf("unsupported format: %s", ps.format)
	}

	return subcommands.ExitSuccess
}
