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
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Mount implements subcommands.Command for the "mount" command.
type Mount struct {
	containerLoader
	fsType  string
	options string
}

// Name implements subcommands.Command.Name.
func (*Mount) Name() string {
	return "mount"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Mount) Synopsis() string {
	return "mount a filesystem inside a running container"
}

// Usage implements subcommands.Command.Usage.
func (*Mount) Usage() string {
	return `mount [options] <container-id> [source] <target>

Where "<container-id>" is the ID of the running container, "<source>" is the
mount source (e.g. host path or "none"), and "<target>" is the absolute path
inside the container where the filesystem will be mounted.

If "<source>" is omitted, it defaults to "none" (useful for in-memory filesystems
like tmpfs).

Example:
  runsc mount -t tmpfs <container-id> /tmp/my-mount
  runsc mount -t tmpfs -o ro,noexec,nosuid <container-id> /tmp/my-mount
  runsc mount -t gofer <container-id> /host/path /container/target
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *Mount) SetFlags(f *flag.FlagSet) {
	f.StringVar(&m.fsType, "type", "", "filesystem type (e.g. tmpfs, gofer)")
	f.StringVar(&m.fsType, "t", "", "alias for --type")
	f.StringVar(&m.options, "options", "", "comma-separated list of mount options (e.g. ro,noexec,nosuid,nodev,noatime)")
	f.StringVar(&m.options, "o", "", "alias for --options")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (m *Mount) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := m.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (m *Mount) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	var source, target string
	switch f.NArg() {
	case 2:
		source = "none"
		target = f.Arg(1)
	case 3:
		source = f.Arg(1)
		target = f.Arg(2)
	default:
		f.Usage()
		return subcommands.ExitUsageError
	}

	if !filepath.IsAbs(target) {
		util.Fatalf("target mount point %q must be an absolute path", target)
	}

	conf := args[0].(*config.Config)

	if m.fsType == "" {
		util.Fatalf("filesystem type (--type / -t) is required")
	}

	c, err := m.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	var flagOpts []string
	var dataOpts []string
	if m.options != "" {
		for _, opt := range strings.Split(m.options, ",") {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}
			if specutils.IsMountFlag(opt) {
				flagOpts = append(flagOpts, opt)
			} else {
				dataOpts = append(dataOpts, opt)
			}
		}
	}

	var files []*os.File
	// When mounting a host path via gofer/9p, spawn a background dynamic-gofer
	// to serve the host directory over a socket pair and pass the socket to Sentry.
	if (m.fsType == "gofer" || m.fsType == "9p") && source != "" && source != "none" && source != "tmpfs" {
		if _, err := os.Stat(source); err != nil {
			util.Fatalf("host source path %q does not exist: %v", source, err)
		}

		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			util.Fatalf("failed to create socket pair for gofer mount: %v", err)
		}
		sentryEnd := os.NewFile(uintptr(fds[0]), "sentry gofer socket")
		goferEnd := os.NewFile(uintptr(fds[1]), "gofer server socket")

		goferCmd := exec.Command(specutils.ExePath, conf.ToFlags()...)
		goferCmd.Args = append(goferCmd.Args, "dynamic-gofer", "--path="+source, "--fd=3")
		if specutils.IsReadonlyMount(flagOpts) {
			goferCmd.Args = append(goferCmd.Args, "--readonly")
		}
		goferCmd.ExtraFiles = append(goferCmd.ExtraFiles, goferEnd)
		goferCmd.SysProcAttr = &unix.SysProcAttr{
			Setsid: true,
		}
		if err := goferCmd.Start(); err != nil {
			util.Fatalf("failed to start dynamic-gofer process: %v", err)
		}
		goferEnd.Close()
		files = append(files, sentryEnd)
	} else if source != "" && source != "none" && source != "tmpfs" {
		file, err := os.Open(source)
		if err != nil {
			util.Fatalf("failed to open host path %q: %v", source, err)
		}
		files = append(files, file)
	}

	opts := &control.MountOpts{
		Source: source,
		Target: target,
		FSType: m.fsType,
		Flags:  uint64(specutils.OptionsToFlags(flagOpts)),
		Data:   strings.Join(dataOpts, ","),
		FilePayload: urpc.FilePayload{
			Files: files,
		},
	}

	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	if err := c.Mount(opts); err != nil {
		util.Fatalf("mount failed: %v", err)
	}

	return subcommands.ExitSuccess
}
