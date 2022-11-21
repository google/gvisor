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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Import imports a map of FDs into the given FDTable. If console is true,
// sets up TTY for sentry stdin, stdout, and stderr FDs. Used FDs are either
// closed or released. It's safe for the caller to close any remaining files
// upon return.
func Import(ctx context.Context, fdTable *kernel.FDTable, console bool, uid auth.KUID, gid auth.KGID, stdioFDs map[int]*fd.FD) (*host.TTYFileDescription, error) {
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
				appFile, err = host.NewFD(ctx, k.HostMount(), hostFD.FD(), &host.NewFDOptions{
					Savable:      true,
					IsTTY:        true,
					VirtualOwner: true,
					UID:          uid,
					GID:          gid,
				})
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
			appFile, err = host.NewFD(ctx, k.HostMount(), hostFD.FD(), &host.NewFDOptions{
				Savable:      true,
				VirtualOwner: true,
				UID:          uid,
				GID:          gid,
			})
			if err != nil {
				return nil, err
			}
			defer appFile.DecRef(ctx)
			hostFD.Release() // FD is transfered to host FD.
		}

		if err := fdTable.NewFDAt(ctx, int32(appFD), appFile, kernel.FDFlags{}); err != nil {
			return nil, err
		}
	}

	if ttyFile == nil {
		return nil, nil
	}
	return ttyFile.Impl().(*host.TTYFileDescription), nil
}
