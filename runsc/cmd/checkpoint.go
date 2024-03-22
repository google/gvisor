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
	"os"
	"path/filepath"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// File containing the container's saved image/state within the given image-path's directory.
const checkpointFileName = "checkpoint.img"

// Checkpoint implements subcommands.Command for the "checkpoint" command.
type Checkpoint struct {
	imagePath    string
	leaveRunning bool
	compression  CheckpointCompression
}

// Name implements subcommands.Command.Name.
func (*Checkpoint) Name() string {
	return "checkpoint"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Checkpoint) Synopsis() string {
	return "checkpoint current state of container (experimental)"
}

// Usage implements subcommands.Command.Usage.
func (*Checkpoint) Usage() string {
	return `checkpoint [flags] <container id> - save current state of container.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Checkpoint) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.imagePath, "image-path", "", "directory path to saved container image")
	f.BoolVar(&c.leaveRunning, "leave-running", false, "restart the container after checkpointing")
	f.Var(newCheckpointCompressionValue(statefile.CompressionLevelFlateBestSpeed, &c.compression), "compression", "compress checkpoint image on disk. Values: none|flate-best-speed.")

	// Unimplemented flags necessary for compatibility with docker.
	var wp string
	f.StringVar(&wp, "work-path", "", "ignored")
}

// Execute implements subcommands.Command.Execute.
func (c *Checkpoint) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	if c.imagePath == "" {
		util.Fatalf("image-path flag must be provided")
	}

	if err := os.MkdirAll(c.imagePath, 0755); err != nil {
		util.Fatalf("making directories at path provided: %v", err)
	}

	fullImagePath := filepath.Join(c.imagePath, checkpointFileName)

	// Create the image file and open for writing.
	file, err := os.OpenFile(fullImagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
	if err != nil {
		util.Fatalf("os.OpenFile(%q) failed: %v", fullImagePath, err)
	}
	defer file.Close()

	sOpts := statefile.Options{Compression: c.compression.Level()}

	if c.leaveRunning {
		// Do not destroy the sandbox after saving.
		sOpts.Resume = true
	}

	if err := cont.Checkpoint(file, sOpts); err != nil {
		util.Fatalf("checkpoint failed: %v", err)
	}

	return subcommands.ExitSuccess
}

// CheckpointCompression represents checkpoint image writer behavior. The
// default behavior is to compress because the default behavior used to be to
// always compress.
type CheckpointCompression statefile.CompressionLevel

func newCheckpointCompressionValue(val statefile.CompressionLevel, p *CheckpointCompression) *CheckpointCompression {
	*p = CheckpointCompression(val)
	return (*CheckpointCompression)(p)
}

// Set implements flag.Value.
func (g *CheckpointCompression) Set(v string) error {
	t, err := statefile.CompressionLevelFromString(v)
	if err != nil {
		return fmt.Errorf("invalid checkpoint compression type %q", v)
	}

	*g = CheckpointCompression(t)

	return nil
}

// Get implements flag.Getter.
func (g *CheckpointCompression) Get() any {
	return *g
}

// String implements flag.Value.
func (g CheckpointCompression) String() string {
	return string(g)
}

// Level returns corresponding statefile.CompressionLevel value.
func (g CheckpointCompression) Level() statefile.CompressionLevel {
	return statefile.CompressionLevel(g)
}
