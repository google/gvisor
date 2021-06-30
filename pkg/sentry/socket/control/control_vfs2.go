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

package control

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// SCMRightsVFS2 represents a SCM_RIGHTS socket control message.
//
// +stateify savable
type SCMRightsVFS2 interface {
	transport.RightsControlMessage

	// Files returns up to max RightsFiles.
	//
	// Returned files are consumed and ownership is transferred to the caller.
	// Subsequent calls to Files will return the next files.
	Files(ctx context.Context, max int) (rf RightsFilesVFS2, truncated bool)
}

// RightsFilesVFS2 represents a SCM_RIGHTS socket control message. A reference
// is maintained for each vfs.FileDescription and is release either when an FD
// is created or when the Release method is called.
//
// +stateify savable
type RightsFilesVFS2 []*vfs.FileDescription

// NewSCMRightsVFS2 creates a new SCM_RIGHTS socket control message
// representation using local sentry FDs.
func NewSCMRightsVFS2(t *kernel.Task, fds []int32) (SCMRightsVFS2, error) {
	files := make(RightsFilesVFS2, 0, len(fds))
	for _, fd := range fds {
		file := t.GetFileVFS2(fd)
		if file == nil {
			files.Release(t)
			return nil, linuxerr.EBADF
		}
		files = append(files, file)
	}
	return &files, nil
}

// Files implements SCMRights.Files.
func (fs *RightsFilesVFS2) Files(ctx context.Context, max int) (RightsFilesVFS2, bool) {
	n := max
	var trunc bool
	if l := len(*fs); n > l {
		n = l
	} else if n < l {
		trunc = true
	}
	rf := (*fs)[:n]
	*fs = (*fs)[n:]
	return rf, trunc
}

// Clone implements transport.RightsControlMessage.Clone.
func (fs *RightsFilesVFS2) Clone() transport.RightsControlMessage {
	nfs := append(RightsFilesVFS2(nil), *fs...)
	for _, nf := range nfs {
		nf.IncRef()
	}
	return &nfs
}

// Release implements transport.RightsControlMessage.Release.
func (fs *RightsFilesVFS2) Release(ctx context.Context) {
	for _, f := range *fs {
		f.DecRef(ctx)
	}
	*fs = nil
}

// rightsFDsVFS2 gets up to the specified maximum number of FDs.
func rightsFDsVFS2(t *kernel.Task, rights SCMRightsVFS2, cloexec bool, max int) ([]int32, bool) {
	files, trunc := rights.Files(t, max)
	fds := make([]int32, 0, len(files))
	for i := 0; i < max && len(files) > 0; i++ {
		fd, err := t.NewFDFromVFS2(0, files[0], kernel.FDFlags{
			CloseOnExec: cloexec,
		})
		files[0].DecRef(t)
		files = files[1:]
		if err != nil {
			t.Warningf("Error inserting FD: %v", err)
			// This is what Linux does.
			break
		}

		fds = append(fds, int32(fd))
	}
	return fds, trunc
}

// PackRightsVFS2 packs as many FDs as will fit into the unused capacity of buf.
func PackRightsVFS2(t *kernel.Task, rights SCMRightsVFS2, cloexec bool, buf []byte, flags int) ([]byte, int) {
	maxFDs := (cap(buf) - len(buf) - linux.SizeOfControlMessageHeader) / 4
	// Linux does not return any FDs if none fit.
	if maxFDs <= 0 {
		flags |= linux.MSG_CTRUNC
		return buf, flags
	}
	fds, trunc := rightsFDsVFS2(t, rights, cloexec, maxFDs)
	if trunc {
		flags |= linux.MSG_CTRUNC
	}
	align := t.Arch().Width()
	return putCmsg(buf, flags, linux.SCM_RIGHTS, align, fds)
}

// NewVFS2 creates default control messages if needed.
func NewVFS2(t *kernel.Task, socketOrEndpoint interface{}, rights SCMRightsVFS2) transport.ControlMessages {
	return transport.ControlMessages{
		Credentials: makeCreds(t, socketOrEndpoint),
		Rights:      rights,
	}
}
