// Copyright 2019 The gVisor Authors.
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

package adaptfstest

import (
	"bytes"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/proc"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/adaptfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func readAll(ctx context.Context, fd *vfs.FileDescription) ([]byte, error) {
	var bb bytes.Buffer
	var buf [bytes.MinRead]byte
	ioseq := usermem.BytesIOSequence(buf[:])
	for {
		n, err := fd.Read(ctx, ioseq, vfs.ReadOptions{})
		if n != 0 {
			bb.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				return bb.Bytes(), nil
			}
			return bb.Bytes(), err
		}
	}
}

func TestAdaptfsProcMeminfo(t *testing.T) {
	k := newTestKernel(t)
	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := vfs.New()
	adaptfs.MustRegisterFilesystemType(vfsObj, "proc")
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "proc", &vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("failed to create procfs root mount: %v", err)
	}
	defer mntns.DecRef(vfsObj)
	root := mntns.Root()
	defer root.DecRef()

	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Pathname:           "meminfo",
		FollowFinalSymlink: true,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		t.Fatalf("failed to open /proc/meminfo: %v", err)
	}
	defer fd.DecRef()
	data, err := readAll(ctx, fd)
	if err != nil {
		t.Fatalf("failed to read /proc/meminfo: %v", err)
	}
	t.Logf("/proc/meminfo contents:\n%s", data)
}
