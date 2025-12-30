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

// Fs includes fs-related functions.
type Fs struct {
	Kernel *kernel.Kernel
}

// TarRootfsUpperLayerOpts contains options for the TarRootfsUpperLayer RPC.
type TarRootfsUpperLayerOpts struct {
	// ContainerID identifies which container's rootfs upper layer should be
	// serialized.
	ContainerID string
	// FilePayload contains the destination for output.
	urpc.FilePayload
}

// Returns a referenced mount namespace for the given container ID,
// or the root container if no ID is provided. Caller must DecRef the
// returned mntns when done.
func (f *Fs) mountNamespaceForContainer(containerID string) (*vfs.MountNamespace, error) {
	if containerID == "" {
		mntns := f.Kernel.GlobalInit().Leader().MountNamespace()
		if mntns == nil {
			return nil, fmt.Errorf("global init mount namespace not found")
		}
		mntns.IncRef()
		return mntns, nil
	}

	var mntns *vfs.MountNamespace
	f.Kernel.TaskSet().ForEachThreadGroup(func(_ *kernel.ThreadGroup, leader *kernel.Task) {
		if mntns != nil {
			return
		}
		if leader.ContainerID() != containerID {
			return
		}
		mntns = leader.GetMountNamespace()
	})
	if mntns == nil {
		return nil, fmt.Errorf("could not find any tasks for %s", containerID)
	}
	return mntns, nil
}

// TarRootfsUpperLayer is a RPC stub which serializes the rootfs upper layer to
// a tar file. When the rootfs is not an overlayfs, it returns an error.
func (f *Fs) TarRootfsUpperLayer(o *TarRootfsUpperLayerOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) != 1 {
		return ErrInvalidFiles
	}
	outFD := o.FilePayload.Files[0]
	defer outFD.Close()

	ctx := f.Kernel.SupervisorContext()
	mntns, err := f.mountNamespaceForContainer(o.ContainerID)
	if err != nil {
		return err
	}
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	ts, ok := root.Mount().Filesystem().Impl().(vfs.TarSerializer)
	if !ok {
		return fmt.Errorf("rootfs is not an overlayfs")
	}
	if err := ts.TarUpperLayer(ctx, outFD); err != nil {
		return fmt.Errorf("failed to serialize rootfs upper layer to tar: %v", err)
	}
	return nil
}

// CatOpts contains options for the Cat RPC call.
type CatOpts struct {
	// Files are the filesystem paths for the files to cat.
	Files []string `json:"files"`

	// FilePayload contains the destination for output.
	urpc.FilePayload
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
	root := mns.Root(ctx)
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
