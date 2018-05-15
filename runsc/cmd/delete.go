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
	"flag"
	"github.com/google/subcommands"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

// Delete implements subcommands.Command for the "delete" command.
type Delete struct {
	// force indicates that the container should be terminated if running.
	force bool
}

// Name implements subcommands.Command.Name.
func (*Delete) Name() string {
	return "delete"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Delete) Synopsis() string {
	return "delete resources held by a container"
}

// Usage implements subcommands.Command.Usage.
func (*Delete) Usage() string {
	return `delete [flags] <container ids>`
}

// SetFlags implements subcommands.Command.SetFlags.
func (d *Delete) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&d.force, "force", false, "terminate container if running")
}

// Execute implements subcommands.Command.Execute.
func (d *Delete) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() == 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*boot.Config)

	for i := 0; i < f.NArg(); i++ {
		id := f.Arg(i)
		c, err := container.Load(conf.RootDir, id)
		if err != nil {
			Fatalf("error loading container %q: %v", id, err)
		}
		if !d.force && (c.Status == container.Running) {
			Fatalf("cannot stop running container without --force flag")
		}
		if err := c.Destroy(); err != nil {
			Fatalf("error destroying container: %v", err)
		}
	}
	return subcommands.ExitSuccess
}
