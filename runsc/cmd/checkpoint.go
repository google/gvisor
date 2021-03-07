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
	"os"
	"path/filepath"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// File containing the container's saved image/state within the given image-path's directory.
const checkpointFileName = "checkpoint.img"

// Checkpoint implements subcommands.Command for the "checkpoint" command.
type Checkpoint struct {
	imagePath    string
	leaveRunning bool
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

	// Unimplemented flags necessary for compatibility with docker.
	var wp string
	f.StringVar(&wp, "work-path", "", "ignored")
}

// Execute implements subcommands.Command.Execute.
func (c *Checkpoint) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {

	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		Fatalf("loading container: %v", err)
	}

	if c.imagePath == "" {
		Fatalf("image-path flag must be provided")
	}

	if err := os.MkdirAll(c.imagePath, 0755); err != nil {
		Fatalf("making directories at path provided: %v", err)
	}

	fullImagePath := filepath.Join(c.imagePath, checkpointFileName)

	// Create the image file and open for writing.
	file, err := os.OpenFile(fullImagePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
	if err != nil {
		Fatalf("os.OpenFile(%q) failed: %v", fullImagePath, err)
	}
	defer file.Close()

	if err := cont.Checkpoint(file); err != nil {
		Fatalf("checkpoint failed: %v", err)
	}

	if !c.leaveRunning {
		return subcommands.ExitSuccess
	}

	// TODO(b/110843694): Make it possible to restore into same container.
	// For now, we can fake it by destroying the container and making a
	// new container with the same ID. This hack does not work with docker
	// which uses the container pid to ensure that the restore-container is
	// actually the same as the checkpoint-container. By restoring into
	// the same container, we will solve the docker incompatibility.

	// Restore into new container with same ID.
	bundleDir := cont.BundleDir
	if bundleDir == "" {
		Fatalf("setting bundleDir")
	}

	spec, err := specutils.ReadSpec(bundleDir, conf)
	if err != nil {
		Fatalf("reading spec: %v", err)
	}

	specutils.LogSpec(spec)

	if cont.ConsoleSocket != "" {
		log.Warningf("ignoring console socket since it cannot be restored")
	}

	if err := cont.Destroy(); err != nil {
		Fatalf("destroying container: %v", err)
	}

	contArgs := container.Args{
		ID:        id,
		Spec:      spec,
		BundleDir: bundleDir,
	}
	cont, err = container.New(conf, contArgs)
	if err != nil {
		Fatalf("restoring container: %v", err)
	}
	defer cont.Destroy()

	if err := cont.Restore(spec, conf, fullImagePath); err != nil {
		Fatalf("starting container: %v", err)
	}

	ws, err := cont.Wait()
	if err != nil {
		Fatalf("Error waiting for container: %v", err)
	}
	*waitStatus = ws

	return subcommands.ExitSuccess
}
