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

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/fsgofer"
)

// DynamicGofer implements subcommands.Command for the "dynamic-gofer" command.
type DynamicGofer struct {
	util.InternalSubCommand
	path     string
	fd       int
	readonly bool
}

// Name implements subcommands.Command.Name.
func (*DynamicGofer) Name() string {
	return "dynamic-gofer"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*DynamicGofer) Synopsis() string {
	return "starts a lisafs server for a dynamically mounted host directory (internal use only)"
}

// Usage implements subcommands.Command.Usage.
func (*DynamicGofer) Usage() string {
	return "dynamic-gofer [flags]\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (d *DynamicGofer) SetFlags(f *flag.FlagSet) {
	f.StringVar(&d.path, "path", "", "host directory path to serve")
	f.IntVar(&d.fd, "fd", -1, "file descriptor to communicate with sentry")
	f.BoolVar(&d.readonly, "readonly", false, "mount as read-only")
}

// Execute implements subcommands.Command.Execute.
func (d *DynamicGofer) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if d.path == "" || d.fd == -1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	if err := fsgofer.OpenProcSelfFD("/proc/self/fd"); err != nil {
		util.Fatalf("fsgofer.OpenProcSelfFD failed: %v", err)
	}

	sock, err := unet.NewSocket(d.fd)
	if err != nil {
		util.Fatalf("creating unet socket on FD %d: %v", d.fd, err)
	}
	defer sock.Close()

	conf := args[0].(*config.Config)
	fsgoferConf := &fsgofer.Config{
		HostUDS:            conf.GetHostUDS(),
		HostFifo:           conf.HostFifo,
		DonateMountPointFD: conf.DirectFS,
	}

	server := lisafs.NewServer()
	connImpl := fsgofer.NewConnectionImpl(fsgoferConf)
	connOpts := fsgofer.ConnectionOpts(d.readonly)

	conn, err := server.CreateConnection(sock, d.path, connOpts, connImpl)
	if err != nil {
		util.Fatalf("creating lisafs connection for path %q: %v", d.path, err)
	}

	server.StartConnection(conn)
	server.Wait()
	server.Destroy()

	return subcommands.ExitSuccess
}
