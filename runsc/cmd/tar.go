// Copyright 2024 The gVisor Authors.
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
	"bytes"
	"context"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Tar implements subcommands.Command for the "tar" command.
type Tar struct{}

// Name implements subcommands.Command.
func (*Tar) Name() string {
	return "tar"
}

// Synopsis implements subcommands.Command.
func (*Tar) Synopsis() string {
	return "creates tar archives from container filesystems"
}

// Usage implements subcommands.Command.
func (*Tar) Usage() string {
	buf := bytes.Buffer{}
	buf.WriteString("Usage: tar <flags> <subcommand> <subcommand args>\n\n")

	cdr := createCommander(&flag.FlagSet{})
	cdr.VisitGroups(func(grp *subcommands.CommandGroup) {
		cdr.ExplainGroup(&buf, grp)
	})

	return buf.String()
}

// SetFlags implements subcommands.Command.
func (*Tar) SetFlags(f *flag.FlagSet) {}

// Execute implements subcommands.Command.
func (*Tar) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	return createCommander(f).Execute(ctx, args...)
}

func createCommander(f *flag.FlagSet) *subcommands.Commander {
	cdr := subcommands.NewCommander(f, "tar")
	cdr.Register(cdr.HelpCommand(), "")
	cdr.Register(cdr.FlagsCommand(), "")
	cdr.Register(new(RootfsUpper), "")
	return cdr
}

// RootfsUpper implements subcommands.Command for the "tar rootfs-upper" command.
type RootfsUpper struct {
	file string
}

// Name implements subcommands.Command.
func (*RootfsUpper) Name() string {
	return "rootfs-upper"
}

// Synopsis implements subcommands.Command.
func (*RootfsUpper) Synopsis() string {
	return "extracts the upper layer of a container's rootfs into a tar archive"
}

// Usage implements subcommands.Command.
func (*RootfsUpper) Usage() string {
	return "rootfs-upper <flags> <container id>\n"
}

// SetFlags implements subcommands.Command.
func (r *RootfsUpper) SetFlags(f *flag.FlagSet) {
	f.StringVar(&r.file, "file", "", "output file path, if empty, output to stdout")
}

// Execute implements subcommands.Command.
func (r *RootfsUpper) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		util.Fatalf("container id must be provided")
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("error loading container: %v", err)
	}

	if c.Sandbox.ID != id {
		util.Fatalf("`tar rootfs-upper` is only supported for the root container as of now")
	}

	util.Infof("Serializing rootfs upper layer into a tar archive for container: %s, sandbox: %s", id, c.Sandbox.ID)

	out := os.Stdout
	if r.file != "" {
		out, err = os.OpenFile(r.file, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			util.Fatalf("failed to open output file: %v", err)
		}
		defer out.Close()
	}

	if err := c.Sandbox.TarRootfsUpperLayer(out); err != nil {
		util.Fatalf("TarRootfsUpperLayer failed: %v", err)
	}
	return subcommands.ExitSuccess
}
