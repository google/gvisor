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

package fsutil

import (
	"bytes"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

type noopBackingFile struct{}

func (noopBackingFile) ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	return dsts.NumBytes(), nil
}

func (noopBackingFile) WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	return srcs.NumBytes(), nil
}

func (noopBackingFile) SetMaskedAttributes(context.Context, fs.AttrMask, fs.UnstableAttr, bool) error {
	return nil
}

func (noopBackingFile) Sync(context.Context) error {
	return nil
}

func (noopBackingFile) FD() int {
	return -1
}

func (noopBackingFile) Allocate(ctx context.Context, offset int64, length int64) error {
	return nil
}

func TestSetPermissions(t *testing.T) {
	ctx := contexttest.Context(t)

	uattr := fs.WithCurrentTime(ctx, fs.UnstableAttr{
		Perms: fs.FilePermsFromMode(0444),
	})
	iops := NewCachingInodeOperations(ctx, noopBackingFile{}, uattr, CachingInodeOperationsOptions{})
	defer iops.Release()

	perms := fs.FilePermsFromMode(0777)
	if !iops.SetPermissions(ctx, nil, perms) {
		t.Fatalf("SetPermissions failed, want success")
	}

	// Did permissions change?
	if iops.attr.Perms != perms {
		t.Fatalf("got perms +%v, want +%v", iops.attr.Perms, perms)
	}

	// Did status change time change?
	if !iops.dirtyAttr.StatusChangeTime {
		t.Fatalf("got status change time not dirty, want dirty")
	}
	if iops.attr.StatusChangeTime.Equal(uattr.StatusChangeTime) {
		t.Fatalf("got status change time unchanged")
	}
}

func TestSetTimestamps(t *testing.T) {
	ctx := contexttest.Context(t)
	for _, test := range []struct {
		desc        string
		ts          fs.TimeSpec
		wantChanged fs.AttrMask
	}{
		{
			desc: "noop",
			ts: fs.TimeSpec{
				ATimeOmit: true,
				MTimeOmit: true,
			},
			wantChanged: fs.AttrMask{},
		},
		{
			desc: "access time only",
			ts: fs.TimeSpec{
				ATime:     ktime.NowFromContext(ctx),
				MTimeOmit: true,
			},
			wantChanged: fs.AttrMask{
				AccessTime: true,
			},
		},
		{
			desc: "modification time only",
			ts: fs.TimeSpec{
				ATimeOmit: true,
				MTime:     ktime.NowFromContext(ctx),
			},
			wantChanged: fs.AttrMask{
				ModificationTime: true,
			},
		},
		{
			desc: "access and modification time",
			ts: fs.TimeSpec{
				ATime: ktime.NowFromContext(ctx),
				MTime: ktime.NowFromContext(ctx),
			},
			wantChanged: fs.AttrMask{
				AccessTime:       true,
				ModificationTime: true,
			},
		},
		{
			desc: "system time access and modification time",
			ts: fs.TimeSpec{
				ATimeSetSystemTime: true,
				MTimeSetSystemTime: true,
			},
			wantChanged: fs.AttrMask{
				AccessTime:       true,
				ModificationTime: true,
			},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			ctx := contexttest.Context(t)

			epoch := ktime.ZeroTime
			uattr := fs.UnstableAttr{
				AccessTime:       epoch,
				ModificationTime: epoch,
				StatusChangeTime: epoch,
			}
			iops := NewCachingInodeOperations(ctx, noopBackingFile{}, uattr, CachingInodeOperationsOptions{})
			defer iops.Release()

			if err := iops.SetTimestamps(ctx, nil, test.ts); err != nil {
				t.Fatalf("SetTimestamps got error %v, want nil", err)
			}
			if test.wantChanged.AccessTime {
				if !iops.attr.AccessTime.After(uattr.AccessTime) {
					t.Fatalf("diritied access time did not advance, want %v > %v", iops.attr.AccessTime, uattr.AccessTime)
				}
				if !iops.dirtyAttr.StatusChangeTime {
					t.Fatalf("dirty access time requires dirty status change time")
				}
				if !iops.attr.StatusChangeTime.After(uattr.StatusChangeTime) {
					t.Fatalf("dirtied status change time did not advance")
				}
			}
			if test.wantChanged.ModificationTime {
				if !iops.attr.ModificationTime.After(uattr.ModificationTime) {
					t.Fatalf("diritied modification time did not advance")
				}
				if !iops.dirtyAttr.StatusChangeTime {
					t.Fatalf("dirty modification time requires dirty status change time")
				}
				if !iops.attr.StatusChangeTime.After(uattr.StatusChangeTime) {
					t.Fatalf("dirtied status change time did not advance")
				}
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	ctx := contexttest.Context(t)

	uattr := fs.UnstableAttr{
		Size: 0,
	}
	iops := NewCachingInodeOperations(ctx, noopBackingFile{}, uattr, CachingInodeOperationsOptions{})
	defer iops.Release()

	if err := iops.Truncate(ctx, nil, uattr.Size); err != nil {
		t.Fatalf("Truncate got error %v, want nil", err)
	}
	var size int64 = 4096
	if err := iops.Truncate(ctx, nil, size); err != nil {
		t.Fatalf("Truncate got error %v, want nil", err)
	}
	if iops.attr.Size != size {
		t.Fatalf("Truncate got %d, want %d", iops.attr.Size, size)
	}
	if !iops.dirtyAttr.ModificationTime || !iops.dirtyAttr.StatusChangeTime {
		t.Fatalf("Truncate did not dirty modification and status change time")
	}
	if !iops.attr.ModificationTime.After(uattr.ModificationTime) {
		t.Fatalf("dirtied modification time did not change")
	}
	if !iops.attr.StatusChangeTime.After(uattr.StatusChangeTime) {
		t.Fatalf("dirtied status change time did not change")
	}
}

type sliceBackingFile struct {
	data []byte
}

func newSliceBackingFile(data []byte) *sliceBackingFile {
	return &sliceBackingFile{data}
}

func (f *sliceBackingFile) ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	r := safemem.BlockSeqReader{safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.data)).DropFirst64(offset)}
	return r.ReadToBlocks(dsts)
}

func (f *sliceBackingFile) WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	w := safemem.BlockSeqWriter{safemem.BlockSeqOf(safemem.BlockFromSafeSlice(f.data)).DropFirst64(offset)}
	return w.WriteFromBlocks(srcs)
}

func (*sliceBackingFile) SetMaskedAttributes(context.Context, fs.AttrMask, fs.UnstableAttr, bool) error {
	return nil
}

func (*sliceBackingFile) Sync(context.Context) error {
	return nil
}

func (*sliceBackingFile) FD() int {
	return -1
}

func (f *sliceBackingFile) Allocate(ctx context.Context, offset int64, length int64) error {
	return syserror.EOPNOTSUPP
}

type noopMappingSpace struct{}

// Invalidate implements memmap.MappingSpace.Invalidate.
func (noopMappingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
}

func anonInode(ctx context.Context) *fs.Inode {
	return fs.NewInode(ctx, &SimpleFileInode{
		InodeSimpleAttributes: NewInodeSimpleAttributes(ctx, fs.FileOwnerFromContext(ctx), fs.FilePermissions{
			User: fs.PermMask{Read: true, Write: true},
		}, 0),
	}, fs.NewPseudoMountSource(ctx), fs.StableAttr{
		Type:      fs.Anonymous,
		BlockSize: hostarch.PageSize,
	})
}

func pagesOf(bs ...byte) []byte {
	buf := make([]byte, 0, len(bs)*hostarch.PageSize)
	for _, b := range bs {
		buf = append(buf, bytes.Repeat([]byte{b}, hostarch.PageSize)...)
	}
	return buf
}

func TestRead(t *testing.T) {
	ctx := contexttest.Context(t)

	// Construct a 3-page file.
	buf := pagesOf('a', 'b', 'c')
	file := fs.NewFile(ctx, fs.NewDirent(ctx, anonInode(ctx), "anon"), fs.FileFlags{}, nil)
	uattr := fs.UnstableAttr{
		Size: int64(len(buf)),
	}
	iops := NewCachingInodeOperations(ctx, newSliceBackingFile(buf), uattr, CachingInodeOperationsOptions{})
	defer iops.Release()

	// Expect the cache to be initially empty.
	if cached := iops.cache.Span(); cached != 0 {
		t.Errorf("Span got %d, want 0", cached)
	}

	// Create a memory mapping of the second page (as CachingInodeOperations
	// expects to only cache mapped pages), then call Translate to force it to
	// be cached.
	var ms noopMappingSpace
	ar := hostarch.AddrRange{hostarch.PageSize, 2 * hostarch.PageSize}
	if err := iops.AddMapping(ctx, ms, ar, hostarch.PageSize, true); err != nil {
		t.Fatalf("AddMapping got %v, want nil", err)
	}
	mr := memmap.MappableRange{hostarch.PageSize, 2 * hostarch.PageSize}
	if _, err := iops.Translate(ctx, mr, mr, hostarch.Read); err != nil {
		t.Fatalf("Translate got %v, want nil", err)
	}
	if cached := iops.cache.Span(); cached != hostarch.PageSize {
		t.Errorf("SpanRange got %d, want %d", cached, hostarch.PageSize)
	}

	// Try to read 4 pages. The first and third pages should be read directly
	// from the "file", the second page should be read from the cache, and only
	// 3 pages (the size of the file) should be readable.
	rbuf := make([]byte, 4*hostarch.PageSize)
	dst := usermem.BytesIOSequence(rbuf)
	n, err := iops.Read(ctx, file, dst, 0)
	if n != 3*hostarch.PageSize || (err != nil && err != io.EOF) {
		t.Fatalf("Read got (%d, %v), want (%d, nil or EOF)", n, err, 3*hostarch.PageSize)
	}
	rbuf = rbuf[:3*hostarch.PageSize]

	// Did we get the bytes we expect?
	if !bytes.Equal(rbuf, buf) {
		t.Errorf("Read back bytes %v, want %v", rbuf, buf)
	}

	// Delete the memory mapping before iops.Release(). The cached page will
	// either be evicted by ctx's pgalloc.MemoryFile, or dropped by
	// iops.Release().
	iops.RemoveMapping(ctx, ms, ar, hostarch.PageSize, true)
}

func TestWrite(t *testing.T) {
	ctx := contexttest.Context(t)

	// Construct a 4-page file.
	buf := pagesOf('a', 'b', 'c', 'd')
	orig := append([]byte(nil), buf...)
	inode := anonInode(ctx)
	uattr := fs.UnstableAttr{
		Size: int64(len(buf)),
	}
	iops := NewCachingInodeOperations(ctx, newSliceBackingFile(buf), uattr, CachingInodeOperationsOptions{})
	defer iops.Release()

	// Expect the cache to be initially empty.
	if cached := iops.cache.Span(); cached != 0 {
		t.Errorf("Span got %d, want 0", cached)
	}

	// Create a memory mapping of the second and third pages (as
	// CachingInodeOperations expects to only cache mapped pages), then call
	// Translate to force them to be cached.
	var ms noopMappingSpace
	ar := hostarch.AddrRange{hostarch.PageSize, 3 * hostarch.PageSize}
	if err := iops.AddMapping(ctx, ms, ar, hostarch.PageSize, true); err != nil {
		t.Fatalf("AddMapping got %v, want nil", err)
	}
	defer iops.RemoveMapping(ctx, ms, ar, hostarch.PageSize, true)
	mr := memmap.MappableRange{hostarch.PageSize, 3 * hostarch.PageSize}
	if _, err := iops.Translate(ctx, mr, mr, hostarch.Read); err != nil {
		t.Fatalf("Translate got %v, want nil", err)
	}
	if cached := iops.cache.Span(); cached != 2*hostarch.PageSize {
		t.Errorf("SpanRange got %d, want %d", cached, 2*hostarch.PageSize)
	}

	// Write to the first 2 pages.
	wbuf := pagesOf('e', 'f')
	src := usermem.BytesIOSequence(wbuf)
	n, err := iops.Write(ctx, src, 0)
	if n != 2*hostarch.PageSize || err != nil {
		t.Fatalf("Write got (%d, %v), want (%d, nil)", n, err, 2*hostarch.PageSize)
	}

	// The first page should have been written directly, since it was not cached.
	want := append([]byte(nil), orig...)
	copy(want, pagesOf('e'))
	if !bytes.Equal(buf, want) {
		t.Errorf("File contents are %v, want %v", buf, want)
	}

	// Sync back to the "backing file".
	if err := iops.WriteOut(ctx, inode); err != nil {
		t.Errorf("Sync got %v, want nil", err)
	}

	// Now the second page should have been written as well.
	copy(want[hostarch.PageSize:], pagesOf('f'))
	if !bytes.Equal(buf, want) {
		t.Errorf("File contents are %v, want %v", buf, want)
	}
}
