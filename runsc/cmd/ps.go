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
	"context"
	"fmt"

	"flag"
	"github.com/google/subcommands"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

// PS implements subcommands.Command for the "ps" command.
type PS struct {
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

// Execute implements subcommands.Command.Execute.
func (ps *PS) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*boot.Config)

	c, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("error loading sandox: %v", err)
	}
	pList, err := c.Processes()
	if err != nil {
		Fatalf("error getting processes for container: %v", err)
	}

	switch ps.format {
	case "table":
		fmt.Println(control.ProcessListToTable(pList))
	case "json":
		o, err := control.PrintPIDsJSON(pList)
		if err != nil {
			Fatalf("error generating JSON: %v", err)
		}
		fmt.Println(o)
	default:
		Fatalf("Unsupported format: %s", ps.format)
	}

	return subcommands.ExitSuccess
}
