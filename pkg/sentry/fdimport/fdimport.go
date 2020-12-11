// Copyright 2020 The gVisor Authors.
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

// Package fdimport provides the Import function.
package fdimport

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/host"
	hostvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Import imports a slice of FDs into the given FDTable. If console is true,
// sets up TTY for the first 3 FDs in the slice representing stdin, stdout,
// stderr. Used FDs are either closed or released. It's safe for the caller to
// close any remaining files upon return.
func Import(ctx context.Context, fdTable *kernel.FDTable, console bool, fds []*fd.FD) (*host.TTYFileOperations, *hostvfs2.TTYFileDescription, error) {
	if kernel.VFS2Enabled {
		ttyFile, err := importVFS2(ctx, fdTable, console, fds)
		return nil, ttyFile, err
	}
	ttyFile, err := importFS(ctx, fdTable, console, fds)
	return ttyFile, nil, err
}

func importFS(ctx context.Context, fdTable *kernel.FDTable, console bool, fds []*fd.FD) (*host.TTYFileOperations, error) {
	var ttyFile *fs.File
	for appFD, hostFD := range fds {
		var appFile *fs.File

		if console && appFD < 3 {
			// Import the file as a host TTY file.
			if ttyFile == nil {
				var err error
				appFile, err = host.ImportFile(ctx, hostFD.FD(), true /* isTTY */)
				if err != nil {
					return nil, err
				}
				defer appFile.DecRef(ctx)
				_ = hostFD.Close() // FD is dup'd i ImportFile.

				// Remember this in the TTY file, as we will
				// use it for the other stdio FDs.
				ttyFile = appFile
			} else {
				// Re-use the existing TTY file, as all three
				// stdio FDs must point to the same fs.File in
				// order to share TTY state, specifically the
				// foreground process group id.
				appFile = ttyFile
			}
		} else {
			// Import the file as a regular host file.
			var err error
			appFile, err = host.ImportFile(ctx, hostFD.FD(), false /* isTTY */)
			if err != nil {
				return nil, err
			}
			defer appFile.DecRef(ctx)
			_ = hostFD.Close() // FD is dup'd i ImportFile.
		}

		// Add the file to the FD map.
		if err := fdTable.NewFDAt(ctx, int32(appFD), appFile, kernel.FDFlags{}); err != nil {
			return nil, err
		}
	}

	if ttyFile == nil {
		return nil, nil
	}
	return ttyFile.FileOperations.(*host.TTYFileOperations), nil
}

func importVFS2(ctx context.Context, fdTable *kernel.FDTable, console bool, stdioFDs []*fd.FD) (*hostvfs2.TTYFileDescription, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, fmt.Errorf("cannot find kernel from context")
	}

	var ttyFile *vfs.FileDescription
	for appFD, hostFD := range stdioFDs {
		var appFile *vfs.FileDescription

		if console && appFD < 3 {
			// Import the file as a host TTY file.
			if ttyFile == nil {
				var err error
				appFile, err = hostvfs2.ImportFD(ctx, k.HostMount(), hostFD.FD(), true /* isTTY */)
				if err != nil {
					return nil, err
				}
				defer appFile.DecRef(ctx)
				hostFD.Release() // FD is transfered to host FD.

				// Remember this in the TTY file, as we will use it for the other stdio
				// FDs.
				ttyFile = appFile
			} else {
				// Re-use the existing TTY file, as all three stdio FDs must point to
				// the same fs.File in order to share TTY state, specifically the
				// foreground process group id.
				appFile = ttyFile
			}
		} else {
			var err error
			appFile, err = hostvfs2.ImportFD(ctx, k.HostMount(), hostFD.FD(), false /* isTTY */)
			if err != nil {
				return nil, err
			}
			defer appFile.DecRef(ctx)
			hostFD.Release() // FD is transfered to host FD.
		}

		if err := fdTable.NewFDAtVFS2(ctx, int32(appFD), appFile, kernel.FDFlags{}); err != nil {
			return nil, err
		}
	}

	if ttyFile == nil {
		return nil, nil
	}
	return ttyFile.Impl().(*hostvfs2.TTYFileDescription), nil
}
