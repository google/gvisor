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

package boot

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/host"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.dev/gvisor/pkg/sentry/limits"
)

// createFDMap creates an FD map that contains stdin, stdout, and stderr. If
// console is true, then ioctl calls will be passed through to the host FD.
// Upon success, createFDMap dups then closes stdioFDs.
func createFDMap(ctx context.Context, l *limits.LimitSet, console bool, stdioFDs []int) (*kernel.FDMap, error) {
	if len(stdioFDs) != 3 {
		return nil, fmt.Errorf("stdioFDs should contain exactly 3 FDs (stdin, stdout, and stderr), but %d FDs received", len(stdioFDs))
	}

	k := kernel.KernelFromContext(ctx)
	fdm := k.NewFDMap()
	defer fdm.DecRef()
	mounter := fs.FileOwnerFromContext(ctx)

	// Maps sandbox FD to host FD.
	fdMap := map[int]int{
		0: stdioFDs[0],
		1: stdioFDs[1],
		2: stdioFDs[2],
	}

	var ttyFile *fs.File
	for appFD, hostFD := range fdMap {
		var appFile *fs.File

		if console && appFD < 3 {
			// Import the file as a host TTY file.
			if ttyFile == nil {
				var err error
				appFile, err = host.ImportFile(ctx, hostFD, mounter, true /* isTTY */)
				if err != nil {
					return nil, err
				}
				defer appFile.DecRef()

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
			appFile, err = host.ImportFile(ctx, hostFD, mounter, false /* isTTY */)
			if err != nil {
				return nil, err
			}
			defer appFile.DecRef()
		}

		// Add the file to the FD map.
		if err := fdm.NewFDAt(kdefs.FD(appFD), appFile, kernel.FDFlags{}, l); err != nil {
			return nil, err
		}
	}

	fdm.IncRef()
	return fdm, nil
}
