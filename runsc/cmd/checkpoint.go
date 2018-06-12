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
	"os"

	"context"
	"flag"
	"github.com/google/subcommands"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/container"
)

// Checkpoint implements subcommands.Command for the "checkpoint" command.
type Checkpoint struct {
	imagePath string
}

// Name implements subcommands.Command.Name.
func (*Checkpoint) Name() string {
	return "checkpoint"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Checkpoint) Synopsis() string {
	return "checkpoint current state of container"
}

// Usage implements subcommands.Command.Usage.
func (*Checkpoint) Usage() string {
	return `checkpoint [flags] <container id> - save current state of container.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Checkpoint) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.imagePath, "image-path", "", "path to saved container image")
}

// Execute implements subcommands.Command.Execute.
func (c *Checkpoint) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {

	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*boot.Config)

	cont, err := container.Load(conf.RootDir, id)
	if err != nil {
		Fatalf("error loading container: %v", err)
	}

	if c.imagePath == "" {
		Fatalf("image-path flag must be provided")
	}

	// Create the image file and open for writing.
	file, err := os.OpenFile(c.imagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
	if err != nil {
		Fatalf("os.OpenFile(%q) failed: %v", c.imagePath, err)
	}
	defer file.Close()

	if err := cont.Checkpoint(file); err != nil {
		Fatalf("checkpoint failed: %v", err)
	}

	return subcommands.ExitSuccess
}
