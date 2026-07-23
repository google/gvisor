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

// Package ebpffd provides file descriptors that refer to eBPF objects.
package ebpffd

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/ebpf"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// ProgramFD represents an eBPF program file descriptor
//
// +stateify savable
type ProgramFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// program is the eBPF program referred to by this file descriptor.
	//
	// Immutable.
	program *ebpf.Program
}

// New returns a new eBPF program file descriptor.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, fileFlags uint32, program *ebpf.Program) (*vfs.FileDescription, error) {
	creds := auth.CredentialsFromContext(ctx)
	fd := &ProgramFD{
		program: program,
	}

	vd := vfsObj.NewAnonVirtualDentry("[bpf-prog]")
	defer vd.DecRef(ctx)

	err := fd.vfsfd.Init(fd, fileFlags, creds, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	})
	if err != nil {
		return nil, err
	}

	return &fd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *ProgramFD) Release(ctx context.Context) {
}

func (fd *ProgramFD) Program() *ebpf.Program {
	return fd.program
}
