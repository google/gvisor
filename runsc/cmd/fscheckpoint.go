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
	"gvisor.dev/gvisor/runsc/sandbox"
)

// FSCheckpoint implements subcommands.Command for the "fscheckpoint" command.
type FSCheckpoint struct {
	containerLoader
	imagePath    string
	leaveRunning bool
	direct       bool
}

// Name implements subcommands.Command.Name.
func (*FSCheckpoint) Name() string {
	return "fscheckpoint"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*FSCheckpoint) Synopsis() string {
	return "checkpoint container filesystems (experimental)"
}

// Usage implements subcommands.Command.Usage.
func (*FSCheckpoint) Usage() string {
	return `fscheckpoint [flags] <container id>:
	Saves sandbox filesystem checkpoint to -image-path directory. Restore checkpoints using "runsc create -fs-restore-image-path=<path>".
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *FSCheckpoint) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.imagePath, "image-path", "", "directory path to saved filesystem checkpoint")
	f.BoolVar(&c.leaveRunning, "leave-running", false, "if true, resume containers after checkpointing; if false, containers exit with status 0 after checkpointing")
	f.BoolVar(&c.direct, "direct", false, "use O_DIRECT for writing checkpoint files")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *FSCheckpoint) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	cont, err := c.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return cont.ID, cont.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (c *FSCheckpoint) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	cont, err := c.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	if c.imagePath == "" {
		util.Fatalf("image-path flag must be provided")
	}

	if err := os.MkdirAll(c.imagePath, 0755); err != nil {
		util.Fatalf("making directories at path provided: %v", err)
	}

	if err := cont.FSSave(conf, c.imagePath, sandbox.FSSaveOpts{
		Direct:          c.direct,
		ExitAfterSaving: !c.leaveRunning,
	}); err != nil {
		util.Fatalf("filesystem checkpoint saving failed: %v", err)
	}

	return subcommands.ExitSuccess
}
