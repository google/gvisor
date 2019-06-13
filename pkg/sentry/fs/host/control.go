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

package host

import (
	"syscall"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/socket/control"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
)

type scmRights struct {
	fds []int
}

func newSCMRights(fds []int) control.SCMRights {
	return &scmRights{fds}
}

// Files implements control.SCMRights.Files.
func (c *scmRights) Files(ctx context.Context, max int) (control.RightsFiles, bool) {
	n := max
	var trunc bool
	if l := len(c.fds); n > l {
		n = l
	} else if n < l {
		trunc = true
	}

	rf := control.RightsFiles(fdsToFiles(ctx, c.fds[:n]))

	// Only consume converted FDs (fdsToFiles may convert fewer than n FDs).
	c.fds = c.fds[len(rf):]
	return rf, trunc
}

// Clone implements transport.RightsControlMessage.Clone.
func (c *scmRights) Clone() transport.RightsControlMessage {
	// Host rights never need to be cloned.
	return nil
}

// Release implements transport.RightsControlMessage.Release.
func (c *scmRights) Release() {
	for _, fd := range c.fds {
		syscall.Close(fd)
	}
	c.fds = nil
}

// If an error is encountered, only files created before the error will be
// returned. This is what Linux does.
func fdsToFiles(ctx context.Context, fds []int) []*fs.File {
	files := make([]*fs.File, 0, len(fds))
	for _, fd := range fds {
		// Get flags. We do it here because they may be modified
		// by subsequent functions.
		fileFlags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		if errno != 0 {
			ctx.Warningf("Error retrieving host FD flags: %v", error(errno))
			break
		}

		// Create the file backed by hostFD.
		file, err := NewFile(ctx, fd, fs.FileOwnerFromContext(ctx))
		if err != nil {
			ctx.Warningf("Error creating file from host FD: %v", err)
			break
		}

		// Set known flags.
		file.SetFlags(fs.SettableFileFlags{
			NonBlocking: fileFlags&syscall.O_NONBLOCK != 0,
		})

		files = append(files, file)
	}
	return files
}
