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
	"path/filepath"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Umount implements subcommands.Command for the user-facing "umount" command.
type Umount struct {
	containerLoader
	force bool
	lazy  bool
}

// Name implements subcommands.Command.Name.
func (*Umount) Name() string {
	return "umount"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Umount) Synopsis() string {
	return "unmount a filesystem inside a running container"
}

// Usage implements subcommands.Command.Usage.
func (*Umount) Usage() string {
	return `umount [options] <container-id> <target>

Where "<container-id>" is the ID of the running container and "<target>" is
the absolute path inside the container where the filesystem is mounted.

Example:
  runsc umount <container-id> /tmp/my-mount
  runsc umount -l <container-id> /tmp/my-mount
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (u *Umount) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&u.force, "force", false, "force unmount")
	f.BoolVar(&u.force, "f", false, "alias for --force")
	f.BoolVar(&u.lazy, "lazy", false, "lazy unmount / detach")
	f.BoolVar(&u.lazy, "l", false, "alias for --lazy")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (u *Umount) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := u.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (u *Umount) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 2 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)
	target := f.Arg(1)

	if !filepath.IsAbs(target) {
		util.Fatalf("target mount point %q must be an absolute path", target)
	}

	c, err := u.loadContainer(conf, f, container.LoadOpts{SkipCheck: true})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	var flags uint32
	if u.force {
		flags |= unix.MNT_FORCE
	}
	if u.lazy {
		flags |= unix.MNT_DETACH
	}

	opts := &control.UmountOpts{
		Target: target,
		Flags:  flags,
	}

	if err := c.Umount(opts); err != nil {
		util.Fatalf("umount failed: %v", err)
	}

	return subcommands.ExitSuccess
}
