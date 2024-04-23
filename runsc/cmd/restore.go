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

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Restore implements subcommands.Command for the "restore" command.
type Restore struct {
	// Restore flags are a super-set of those for Create.
	Create

	// imagePath is the path to the saved container image
	imagePath string

	// detach indicates that runsc has to start a process and exit without waiting it.
	detach bool

	// direct indicates whether O_DIRECT should be used for reading the
	// checkpoint pages file. It is faster if the checkpoint files are not
	// already in the page cache (for example if its coming from an untouched
	// network block device). Usually the restore is done only once, so the cost
	// of adding the checkpoint files to the page cache can be redundant.
	direct bool
}

// Name implements subcommands.Command.Name.
func (*Restore) Name() string {
	return "restore"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Restore) Synopsis() string {
	return "restore a saved state of container (experimental)"
}

// Usage implements subcommands.Command.Usage.
func (*Restore) Usage() string {
	return `restore [flags] <container id> - restore saved state of container.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Restore) SetFlags(f *flag.FlagSet) {
	r.Create.SetFlags(f)
	f.StringVar(&r.imagePath, "image-path", "", "directory path to saved container image")
	f.BoolVar(&r.detach, "detach", false, "detach from the container's process")
	f.BoolVar(&r.direct, "direct", false, "use O_DIRECT for reading checkpoint pages file")

	// Unimplemented flags necessary for compatibility with docker.

	var nsr bool
	f.BoolVar(&nsr, "no-subreaper", false, "ignored")

	var wp string
	f.StringVar(&wp, "work-path", "", "ignored")
}

// Execute implements subcommands.Command.Execute.
func (r *Restore) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	if conf.Rootless {
		return util.Errorf("Rootless mode not supported with %q", r.Name())
	}

	bundleDir := r.bundleDir
	if bundleDir == "" {
		bundleDir = getwdOrDie()
	}
	if r.imagePath == "" {
		return util.Errorf("image-path flag must be provided")
	}

	var cu cleanup.Cleanup
	defer cu.Clean()

	runArgs := container.Args{
		ID:            id,
		Spec:          nil,
		BundleDir:     bundleDir,
		ConsoleSocket: r.consoleSocket,
		PIDFile:       r.pidFile,
		UserLog:       r.userLog,
		Attached:      !r.detach,
	}

	log.Debugf("Restore container, cid: %s, rootDir: %q", id, conf.RootDir)
	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		if err != os.ErrNotExist {
			return util.Errorf("loading container: %v", err)
		}

		log.Warningf("Container not found, creating new one, cid: %s, spec from: %s", id, bundleDir)

		// Read the spec again here to ensure flag annotations from the spec are
		// applied to "conf".
		if runArgs.Spec, err = specutils.ReadSpec(bundleDir, conf); err != nil {
			return util.Errorf("reading spec: %v", err)
		}
		specutils.LogSpecDebug(runArgs.Spec, conf.OCISeccomp)

		if c, err = container.New(conf, runArgs); err != nil {
			return util.Errorf("creating container: %v", err)
		}

		// Clean up partially created container if an error occurs.
		// Any errors returned by Destroy() itself are ignored.
		cu.Add(func() {
			c.Destroy()
		})
	} else {
		runArgs.Spec = c.Spec
	}

	log.Debugf("Restore: %v", r.imagePath)
	if err := c.Restore(conf, r.imagePath, r.direct); err != nil {
		return util.Errorf("starting container: %v", err)
	}

	// If we allocate a terminal, forward signals to the sandbox process.
	// Otherwise, Ctrl+C will terminate this process and its children,
	// including the terminal.
	if c.Spec.Process.Terminal {
		stopForwarding := c.ForwardSignals(0, true /* fgProcess */)
		defer stopForwarding()
	}

	var ws unix.WaitStatus
	if runArgs.Attached {
		if ws, err = c.Wait(); err != nil {
			return util.Errorf("running container: %v", err)
		}
	}
	*waitStatus = ws

	cu.Release()

	return subcommands.ExitSuccess
}
