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
	"strconv"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/sandboxsetup"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

type imagePaths []string

// String implements flag.Value.String.
func (p *imagePaths) String() string {
	return strings.Join(*p, ",")
}

// Get implements flag.Value.Get.
func (p *imagePaths) Get() any {
	return p
}

// Set implements flag.Value.Set. Set(String()) should be idempotent.
func (p *imagePaths) Set(value string) error {
	*p = append(*p, strings.Split(value, ",")...)
	return nil
}

// Create implements subcommands.Command for the "create" command.
type Create struct {
	// bundleDir is the path to the bundle directory (defaults to the
	// current working directory).
	bundleDir string

	// pidFile is the filename that the sandbox pid will be written to.
	// This file should only be created once the container process inside
	// the sandbox is ready to use.
	pidFile string

	// consoleSocket is the path to an AF_UNIX socket which will receive a
	// file descriptor referencing the master end of the console's
	// pseudoterminal.  This is ignored unless spec.Process.Terminal is
	// true.
	consoleSocket string

	// passFDs are host FDs exposed to the sandboxed application.
	passFDs sandboxsetup.FDMappings

	// goferFDs are host FDs connected to lisafs gofers that the caller runs,
	// keyed by mount destination.
	goferFDs goferFDFlags

	// userLog is the path to send user-visible logs to. This log is different
	// from debug logs. The former is meant to be consumed by the users and should
	// contain only information that is relevant to the person running the
	// container, e.g. unsupported syscalls, while the later is more verbose and
	// consumed by developers.
	userLog string

	// fsRestoreImagePaths is the list of paths to the filesystem checkpoints to
	// restore. Combining bundles from different checkpoints is only supported on
	// fresh container creation (create/run); during restore, all bundles must
	// come from the same checkpoint as the sentry state image.
	// fsRestoreDirect is true if files making up the filesystem checkpoint should
	// be opened with O_DIRECT.
	fsRestoreImagePaths imagePaths
	fsRestoreDirect     bool

	// noRootContainer creates a sandbox with no root container: the spec holds
	// sandbox-wide settings only and containers are added afterwards.
	noRootContainer bool

	// spec is the cached OCI spec.
	spec *specs.Spec
}

// Name implements subcommands.Command.Name.
func (*Create) Name() string {
	return "create"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Create) Synopsis() string {
	return "create a secure container"
}

// Usage implements subcommands.Command.Usage.
func (*Create) Usage() string {
	return "create [flags] <container id> - create a secure container\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Create) SetFlags(f *flag.FlagSet) {
	f.Var(&c.goferFDs, "gofer-fd", "lisafs connection to a gofer that the caller runs, in DEST:FD or DEST:FD:CONF format, where DEST is the mount destination (/ for the rootfs), FD is the host file descriptor, and CONF says how the gofer backs the mount (e.g. lisafs:memory; defaults to deriving it from --overlay2 and the spec). Every lisafs-backed mount of the root container needs one (can be supplied multiple times). When set, runsc starts no gofer")
	f.Var(&c.passFDs, "pass-fd", "file descriptor passed to the container in M:N format, where M is the host and N is the guest descriptor (can be supplied multiple times)")
	f.StringVar(&c.bundleDir, "bundle", "", "path to the root of the bundle directory, defaults to the current directory")
	f.StringVar(&c.consoleSocket, "console-socket", "", "path to an AF_UNIX socket which will receive a file descriptor referencing the master end of the console's pseudoterminal")
	f.StringVar(&c.pidFile, "pid-file", "", "filename that the container pid will be written to")
	f.StringVar(&c.userLog, "user-log", "", "filename to send user-visible logs to. Empty means no logging.")
	f.Var(&c.fsRestoreImagePaths, "fs-restore-image-path", "path to filesystem checkpoint (<dir> or <dir>/<prefix>) to restore (can be repeated; combining bundles from different checkpoints is only supported for create/run, not restore)")
	f.BoolVar(&c.fsRestoreDirect, "fs-restore-direct", false, "open files in fs-restore-image-path with O_DIRECT")
	f.BoolVar(&c.noRootContainer, "no-root-container", false, "create a sandbox with no root container; the bundle spec describes only the sandbox and containers are added later as subcontainers")
}

// passFiles takes ownership of the descriptors supplied by --pass-fd. The
// caller must close them after donating them to the new sandbox.
func (c *Create) passFiles() (map[int]*os.File, func(), error) {
	files := make(map[int]*os.File, len(c.passFDs))
	hostFiles := make(map[int]*os.File, len(c.passFDs))
	var cu cleanup.Cleanup
	defer cu.Clean()
	for _, mapping := range c.passFDs {
		file, ok := hostFiles[mapping.Host]
		if !ok {
			file = os.NewFile(uintptr(mapping.Host), "")
			if file == nil {
				return nil, nil, fmt.Errorf("creating file from descriptor %d", mapping.Host)
			}
			hostFiles[mapping.Host] = file
			cu.Add(func() {
				if err := file.Close(); err != nil {
					log.Debugf("Closing passed FD %d: %v", mapping.Host, err)
				}
			})
		}
		files[mapping.Guest] = file
	}
	return files, cu.Release(), nil
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *Create) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	if f.NArg() < 1 {
		return "", nil, fmt.Errorf("a container id is required")
	}
	cid := f.Arg(0)
	if c.spec != nil {
		return cid, c.spec, nil
	}
	if c.bundleDir == "" {
		c.bundleDir = getwdOrDie()
	}
	spec, err := specutils.ReadSpec(c.bundleDir, specutils.SpecOpts{Conf: conf, NoRootContainer: c.noRootContainer})
	if err != nil {
		return cid, nil, fmt.Errorf("reading spec: %w", err)
	}
	c.spec = spec
	return cid, c.spec, nil
}

// Execute implements subcommands.Command.Execute.
func (c *Create) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	if conf.Rootless {
		return util.Errorf("Rootless mode not supported with %q", c.Name())
	}

	id, spec, err := c.FetchSpec(conf, f)
	if err != nil {
		return util.Errorf("FetchSpec: %v", err)
	}
	files, closeFiles, err := c.passFiles()
	if err != nil {
		return util.Errorf("preparing passed files: %v", err)
	}
	defer closeFiles()

	// Create the container. A new sandbox will be created for the
	// container unless the metadata specifies that it should be run in an
	// existing container.
	contArgs := container.Args{
		ID:                  id,
		Spec:                spec,
		BundleDir:           c.bundleDir,
		ConsoleSocket:       c.consoleSocket,
		PIDFile:             c.pidFile,
		UserLog:             c.userLog,
		PassFiles:           files,
		FSRestoreImagePaths: []string(c.fsRestoreImagePaths),
		FSRestoreDirect:     c.fsRestoreDirect,
		NoRootContainer:     c.noRootContainer,
		GoferFiles:          c.goferFiles(),
	}
	if _, err := container.New(conf, contArgs); err != nil {
		return util.Errorf("creating container: %v", err)
	}
	return subcommands.ExitSuccess
}

// goferFiles returns the --gofer-fd connections.
func (c *Create) goferFiles() []container.GoferFile {
	var files []container.GoferFile
	for _, g := range c.goferFDs {
		files = append(files, container.GoferFile{
			Destination: g.dest,
			File:        os.NewFile(uintptr(g.fd), "gofer FD"),
			Conf:        g.conf,
		})
	}
	return files
}

// goferFD is one --gofer-fd value.
type goferFD struct {
	dest string
	fd   int
	conf *specutils.GoferMountConf
}

// goferFDFlags implements flag.Value for --gofer-fd, which may be supplied
// multiple times.
type goferFDFlags []goferFD

// String implements flag.Value.
func (g *goferFDFlags) String() string {
	vals := make([]string, 0, len(*g))
	for _, v := range *g {
		s := fmt.Sprintf("%s:%d", v.dest, v.fd)
		if v.conf != nil {
			s += ":" + v.conf.String()
		}
		vals = append(vals, s)
	}
	return strings.Join(vals, " ")
}

// Get implements flag.Getter.
func (g *goferFDFlags) Get() any {
	return g
}

// Set implements flag.Value. Mount destinations that contain ':' are not
// supported.
func (g *goferFDFlags) Set(s string) error {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 2 {
		return fmt.Errorf("invalid gofer FD %q: want DEST:FD or DEST:FD:CONF", s)
	}
	fd, err := strconv.Atoi(parts[1])
	if err != nil || fd < 0 {
		return fmt.Errorf("invalid gofer FD %q: %q is not a file descriptor", s, parts[1])
	}
	v := goferFD{dest: parts[0], fd: fd}
	if len(parts) == 3 {
		v.conf = &specutils.GoferMountConf{}
		if err := v.conf.Set(parts[2]); err != nil {
			return fmt.Errorf("invalid gofer FD %q: %w", s, err)
		}
	}
	*g = append(*g, v)
	return nil
}
