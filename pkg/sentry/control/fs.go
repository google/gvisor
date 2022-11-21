// Copyright 2021 The gVisor Authors.
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
	"fmt"
	"io"
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/pkg/usermem"
)

// CatOpts contains options for the Cat RPC call.
type CatOpts struct {
	// Files are the filesystem paths for the files to cat.
	Files []string `json:"files"`

	// FilePayload contains the destination for output.
	urpc.FilePayload
}

// Fs includes fs-related functions.
type Fs struct {
	Kernel *kernel.Kernel
}

// Cat is a RPC stub which prints out and returns the content of the files.
func (f *Fs) Cat(o *CatOpts, _ *struct{}) error {
	// Create an output stream.
	if len(o.FilePayload.Files) != 1 {
		return ErrInvalidFiles
	}

	output := o.FilePayload.Files[0]
	for _, file := range o.Files {
		if err := cat(f.Kernel, file, output); err != nil {
			return fmt.Errorf("cannot read from file %s: %v", file, err)
		}
	}

	return nil
}

// fdReader provides an io.Reader interface for a vfs.FileDescription.
type fdReader struct {
	ctx context.Context
	fd  *vfs.FileDescription
}

// Read implements io.Reader.Read.
func (f *fdReader) Read(p []byte) (int, error) {
	n, err := f.fd.Read(f.ctx, usermem.BytesIOSequence(p), vfs.ReadOptions{})
	return int(n), err
}

func cat(k *kernel.Kernel, path string, output *os.File) error {
	ctx := k.SupervisorContext()
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	mns := k.GlobalInit().Leader().MountNamespace()
	root := mns.Root()
	defer root.DecRef(ctx)

	fd, err := k.VFS().OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(path),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer fd.DecRef(ctx)

	_, err = io.Copy(output, &fdReader{ctx: ctx, fd: fd})
	return err
}
