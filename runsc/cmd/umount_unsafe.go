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
	"os"
	"syscall"
	"unsafe"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// HostUmount implements subcommands.Command for the "host-umount" command.
type HostUmount struct {
	syncFD int
}

// Name implements subcommands.Command.Name.
func (*HostUmount) Name() string {
	return "host-umount"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*HostUmount) Synopsis() string {
	return "lazily unmount a host directory when the synchronization file is closed (internal use only)"
}

// Usage implements subcommands.Command.Usage.
func (*HostUmount) Usage() string {
	return `host-umount --sync-fd=FD <directory path>
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (u *HostUmount) SetFlags(f *flag.FlagSet) {
	f.IntVar(&u.syncFD, "sync-fd", -1, "file descriptor that has to be closed when the mount isn't needed")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (*HostUmount) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// Execute implements subcommands.Command.Execute.
func (u *HostUmount) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 || u.syncFD == -1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	dirPath := f.Arg(0)

	syncFile := os.NewFile(uintptr(u.syncFD), "sync file")
	defer syncFile.Close()

	buf := make([]byte, 1)
	if l, err := syncFile.Read(buf); err != nil || l != 1 {
		util.Fatalf("unable to read from the sync descriptor: %v, error %v", l, err)
	}

	if _, _, errno := unix.RawSyscall(
		unix.SYS_UMOUNT2,
		uintptr(unsafe.Pointer(syscall.StringBytePtr(dirPath))),
		uintptr(linux.MNT_DETACH), 0); errno != 0 {
		util.Fatalf("Unable to umount %s: errno %v", dirPath, errno)
	}

	return subcommands.ExitSuccess
}
