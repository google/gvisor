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

package tmpfs

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

func newFileInode(ctx context.Context) *fs.Inode {
	m := fs.NewCachingMountSource(&Filesystem{}, fs.MountSourceFlags{})
	iops := NewInMemoryFile(ctx, usage.Tmpfs, fs.WithCurrentTime(ctx, fs.UnstableAttr{}))
	return fs.NewInode(iops, m, fs.StableAttr{
		DeviceID:  tmpfsDevice.DeviceID(),
		InodeID:   tmpfsDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      fs.RegularFile,
	})
}

func newFile(ctx context.Context) *fs.File {
	inode := newFileInode(ctx)
	f, _ := inode.GetFile(ctx, fs.NewDirent(inode, "stub"), fs.FileFlags{Read: true, Write: true})
	return f
}

// Allocate once, write twice.
func TestGrow(t *testing.T) {
	ctx := contexttest.Context(t)
	f := newFile(ctx)
	defer f.DecRef()

	abuf := bytes.Repeat([]byte{'a'}, 68)
	n, err := f.Pwritev(ctx, usermem.BytesIOSequence(abuf), 0)
	if n != int64(len(abuf)) || err != nil {
		t.Fatalf("Pwritev got (%d, %v) want (%d, nil)", n, err, len(abuf))
	}

	bbuf := bytes.Repeat([]byte{'b'}, 856)
	n, err = f.Pwritev(ctx, usermem.BytesIOSequence(bbuf), 68)
	if n != int64(len(bbuf)) || err != nil {
		t.Fatalf("Pwritev got (%d, %v) want (%d, nil)", n, err, len(bbuf))
	}

	rbuf := make([]byte, len(abuf)+len(bbuf))
	n, err = f.Preadv(ctx, usermem.BytesIOSequence(rbuf), 0)
	if n != int64(len(rbuf)) || err != nil {
		t.Fatalf("Preadv got (%d, %v) want (%d, nil)", n, err, len(rbuf))
	}

	if want := append(abuf, bbuf...); !bytes.Equal(rbuf, want) {
		t.Fatalf("Read %v, want %v", rbuf, want)
	}
}
