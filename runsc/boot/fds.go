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
)

// createFDTable creates an FD table that contains stdin, stdout, and stderr.
// If console is true, then ioctl calls will be passed through to the host FD.
// Upon success, createFDMap dups then closes stdioFDs.
func createFDTable(ctx context.Context, console bool, stdioFDs []int) (*kernel.FDTable, error) {
	if len(stdioFDs) != 3 {
		return nil, fmt.Errorf("stdioFDs should contain exactly 3 FDs (stdin, stdout, and stderr), but %d FDs received", len(stdioFDs))
	}

	k := kernel.KernelFromContext(ctx)
	fdTable := k.NewFDTable()
	defer fdTable.DecRef()
	mounter := fs.FileOwnerFromContext(ctx)

	var ttyFile *fs.File
	for appFD, hostFD := range stdioFDs {
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
		if err := fdTable.NewFDAt(ctx, int32(appFD), appFile, kernel.FDFlags{}); err != nil {
			return nil, err
		}
	}

	fdTable.IncRef()
	return fdTable, nil
}
