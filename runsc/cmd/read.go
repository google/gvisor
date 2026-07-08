// Copyright 2026 The gVisor Authors.
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
	"os"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Read implements subcommands.Command for the "read" command.
type Read struct {
	containerLoader
	size int64
}

// Name implements subcommands.Command.Name.
func (*Read) Name() string {
	return "read"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Read) Synopsis() string {
	return "read a file of the sandbox given the path"
}

// Usage implements subcommands.Command.Usage.
func (*Read) Usage() string {
	return `read [flags] <container-id> <path> - read a file of the sandbox given the path

Where "<container-id>" is the name for the instance of the container, and
"<path>" is the path to the file in the sandbox to read. Size can be specified via the --size flag.

EXAMPLE:
       # runsc read --size 4096 <container-id> /etc/passwd
       # runsc read <container-id> /etc/passwd
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Read) SetFlags(f *flag.FlagSet) {
	f.Int64Var(&r.size, "size", 0, "maximum size to read (0 means unlimited)")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (r *Read) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := r.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (r *Read) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 2 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	path := f.Arg(1)
	size := r.size

	conf := args[0].(*config.Config)
	c, err := r.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		util.Fatalf("Failed to load container: %v", err)
	}

	if err := c.Sandbox.ReadFile(c.ID, path, size, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
