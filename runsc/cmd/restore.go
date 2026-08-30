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
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
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

	containerLoader

	// imagePaths is the list of paths to the saved container image(s).
	imagePaths imagePathsVar

	// detach indicates that runsc has to start a process and exit without waiting it.
	detach bool

	// direct indicates whether O_DIRECT should be used for reading the
	// checkpoint pages file. It is faster if the checkpoint files are not
	// already in the page cache (for example if its coming from an untouched
	// network block device). Usually the restore is done only once, so the cost
	// of adding the checkpoint files to the page cache can be redundant.
	direct bool

	// If background is true, the container image may continue to be read after
	// the restore command exits. For large images, this significantly shortens
	// the amount of time taken by the restore command. The checkpoint must be
	// uncompressed for background to work; if the checkpoint is compressed,
	// background has no effect.
	background bool
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
	return "restore [flags] <container id> - restore saved state of container.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (r *Restore) SetFlags(f *flag.FlagSet) {
	r.Create.SetFlags(f)
	f.Var(&r.imagePaths, "image-path", "directory path to saved container image (can be specified up to two times: first for Sentry state, second for filesystem checkpoint)")
	f.BoolVar(&r.detach, "detach", false, "detach from the container's process")
	f.BoolVar(&r.direct, "direct", false, "use O_DIRECT for reading checkpoint pages file")
	f.BoolVar(&r.background, "background", false, "allow image loading to continue after restore exits (requires uncompressed checkpoint)")

	// Unimplemented flags necessary for compatibility with docker.

	var nsr bool
	f.BoolVar(&nsr, "no-subreaper", false, "ignored")

	var wp string
	f.StringVar(&wp, "work-path", "", "ignored")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (r *Restore) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	if f.NArg() != 1 {
		return "", nil, fmt.Errorf("a container id is required")
	}
	id := f.Arg(0)

	// If the spec is already set via Create.FetchSpec(), use it.
	if r.spec != nil {
		return id, r.spec, nil
	}

	// Try loading the container first, similar to Execute().
	c, err := r.loadContainer(conf, f, container.LoadOpts{})
	if err == nil {
		return c.ID, c.Spec, nil
	}
	if err != os.ErrNotExist {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}

	// Container not found. Fallback to reading spec from bundle.
	return r.Create.FetchSpec(conf, f)
}

type imagePathsVar []string

// String implements flag.Value.String.
func (v *imagePathsVar) String() string {
	if v == nil {
		return ""
	}
	return strings.Join(*v, ",")
}

// Get implements flag.Value.Get.
func (v *imagePathsVar) Get() any {
	if v == nil {
		return []string(nil)
	}
	return []string(*v)
}

// Set implements flag.Value.Set.
func (v *imagePathsVar) Set(s string) error {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*v = append(*v, part)
		}
	}
	return nil
}

func parseRestoreImagePaths(imagePaths []string) ([]string, error) {
	var paths []string
	for _, p := range imagePaths {
		for _, part := range strings.Split(p, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				paths = append(paths, part)
			}
		}
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("image-path flag must be provided")
	}
	if len(paths) > 2 {
		return nil, fmt.Errorf("at most 2 image-path flags are supported, got %d", len(paths))
	}
	return paths, nil
}

func resolveRestorePaths(paths []string, flagFSRestoreImagePath string) (string, string, bool, error) {
	if len(paths) == 1 {
		checkpointDirPath := paths[0]
		fsRestoreImagePath := flagFSRestoreImagePath
		combinedFSRestore := flagFSRestoreImagePath != ""
		return checkpointDirPath, fsRestoreImagePath, combinedFSRestore, nil
	}
	if flagFSRestoreImagePath != "" && filepath.Clean(flagFSRestoreImagePath) != filepath.Clean(paths[1]) {
		return "", "", false, fmt.Errorf("conflicting filesystem checkpoint paths: %q from image-path and %q from fs-restore-image-path", paths[1], flagFSRestoreImagePath)
	}
	return paths[0], paths[1], true, nil
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

	paths, err := parseRestoreImagePaths(r.imagePaths)
	if err != nil {
		return util.Errorf("%v", err)
	}

	checkpointDirPath, fsRestoreImagePath, combinedFSRestore, err := resolveRestorePaths(paths, r.fsRestoreImagePath)
	if err != nil {
		return util.Errorf("%v", err)
	}

	var cu cleanup.Cleanup
	defer cu.Clean()

	runArgs := container.Args{
		ID:                 id,
		Spec:               nil,
		BundleDir:          bundleDir,
		ConsoleSocket:      r.consoleSocket,
		PIDFile:            r.pidFile,
		UserLog:            r.userLog,
		Attached:           !r.detach,
		FSRestoreImagePath: fsRestoreImagePath,
		FSRestoreDirect:    r.fsRestoreDirect || r.direct,
		CheckpointDirPath:  checkpointDirPath,
		CombinedFSRestore:  combinedFSRestore,
	}

	log.Debugf("Restore container, cid: %s, rootDir: %q", id, conf.RootDir)
	c, err := r.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		if err != os.ErrNotExist {
			return util.Errorf("loading container: %v", err)
		}

		log.Warningf("Container not found, creating new one, cid: %s, spec from: %s", id, bundleDir)

		// Read the spec from the bundle directory.
		if r.spec == nil {
			if r.spec, err = specutils.ReadSpec(bundleDir, conf); err != nil {
				return util.Errorf("reading spec: %v", err)
			}
		}
		runArgs.Spec = r.spec
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

	log.Debugf("Restore: %v", checkpointDirPath)
	err = c.Restore(conf, checkpointDirPath, r.direct, r.background, nil /* networkArgs */)
	if err != nil {
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
