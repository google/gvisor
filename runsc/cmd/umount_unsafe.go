// Copyright 2022 The gVisor Authors.
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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// Umount implements subcommands.Command for the "kill" command.
type Umount struct {
	syncFD int
}

// Name implements subcommands.Command.Name.
func (*Umount) Name() string {
	return "umount"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Umount) Synopsis() string {
	return "umount the specified directory when one byte is read from synd-fd"
}

// Usage implements subcommands.Command.Usage.
func (*Umount) Usage() string {
	return `umount --synd-fd=FD <directory path>`
}

// SetFlags implements subcommands.Command.SetFlags.
func (u *Umount) SetFlags(f *flag.FlagSet) {
	f.IntVar(&u.syncFD, "sync-fd", -1, "")
}

// Execute implements subcommands.Command.Execute.
func (u *Umount) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() == 0 || f.NArg() > 1 {
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
