// Copyright 2018 Google LLC
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
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type noopBackingFile struct{}

func (noopBackingFile) ReadToBlocksAt(ctx context.Context, dsts safemem.BlockSeq, offset uint64) (uint64, error) {
	return dsts.NumBytes(), nil
}

func (noopBackingFile) WriteFromBlocksAt(ctx context.Context, srcs safemem.BlockSeq, offset uint64) (uint64, error) {
	return srcs.NumBytes(), nil
}

func (noopBackingFile) SetMaskedAttributes(context.Context, fs.AttrMask, fs.UnstableAttr) error {
	return nil
}

func (noopBackingFile) Sync(context.Context) error {
	return nil
}

func (noopBackingFile) FD() int {
	return -1
}

func TestSetPermissions(t *testing.T) {
	ctx := contexttest.Context(t)

	uattr := fs.WithCurrentTime(ctx, fs.UnstableAttr{
		Perms: fs.FilePermsFromMode(0444),
	})
	iops := NewCachingInodeOperations(ctx, noopBackingFile{}, uattr, false /*forcePageCache*/)
	defer iops.Release()

	perms := fs.FilePermsFromMode(0777)
	if !iops.SetPermissions(ctx, nil, perms) {
		t.Fatalf("SetPermissions failed, want success")
	}

	// Did permissions change?
	if !iops.dirtyAttr.Perms {
		t.Fatalf("got perms not dirty, want dirty")
	}
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
		desc      string
		ts        fs.TimeSpec
		wantDirty fs.AttrMask
	}{
		{
			desc: "noop",
			ts: fs.TimeSpec{
				ATimeOmit: true,
				MTimeOmit: true,
			},
			wantDirty: fs.AttrMask{},
		},
		{
			desc: "access time only",
			ts: fs.TimeSpec{
				ATime:     ktime.NowFromContext(ctx),
				MTimeOmit: true,
			},
			wantDirty: fs.AttrMask{
				AccessTime:       true,
				StatusChangeTime: true,
			},
		},
		{
			desc: "modification time only",
			ts: fs.TimeSpec{
				ATimeOmit: true,
				MTime:     ktime.NowFromContext(ctx),
			},
			wantDirty: fs.AttrMask{
				ModificationTime: true,
				StatusChangeTime: true,
			},
		},
		{
			desc: "access and modification time",
			ts: fs.TimeSpec{
				ATime: ktime.NowFromContext(ctx),
				MTime: ktime.NowFromContext(ctx),
			},
			wantDirty: fs.AttrMask{
				AccessTime:       true,
				ModificationTime: true,
				StatusChangeTime: true,
			},
		},
		{
			desc: "system time access and modification time",
			ts: fs.TimeSpec{
				ATimeSetSystemTime: true,
				MTimeSetSystemTime: true,
			},
			wantDirty: fs.AttrMask{
				AccessTime:       true,
				ModificationTime: true,
				StatusChangeTime: true,
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
			iops := NewCachingInodeOperations(ctx, noopBackingFile{}, uattr, false /*forcePageCache*/)
			defer iops.Release()

			if err := iops.SetTimestamps(ctx, nil, test.ts); err != nil {
				t.Fatalf("SetTimestamps got error %v, want nil", err)
			}
			if !reflect.DeepEqual(iops.dirtyAttr, test.wantDirty) {
				t.Fatalf("dirty got %+v, want %+v", iops.dirtyAttr, test.wantDirty)
			}
			if iops.dirtyAttr.AccessTime {
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
			if iops.dirtyAttr.ModificationTime {
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
	iops := NewCachingInodeOperations(ctx, noopBackingFile{}, uattr, false /*forcePageCache*/)
	defer iops.Release()

	if err := iops.Truncate(ctx, nil, uattr.Size); err != nil {
		t.Fatalf("Truncate got error %v, want nil", err)
	}
	if iops.dirtyAttr.Size {
		t.Fatalf("Truncate caused size to be dirtied")
	}
	var size int64 = 4096
	if err := iops.Truncate(ctx, nil, size); err != nil {
		t.Fatalf("Truncate got error %v, want nil", err)
	}
	if !iops.dirtyAttr.Size {
		t.Fatalf("Truncate caused size to not be dirtied")
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

func (*sliceBackingFile) SetMaskedAttributes(context.Context, fs.AttrMask, fs.UnstableAttr) error {
	return nil
}

func (*sliceBackingFile) Sync(context.Context) error {
	return nil
}

func (*sliceBackingFile) FD() int {
	return -1
}

type noopMappingSpace struct{}

// Invalidate implements memmap.MappingSpace.Invalidate.
func (noopMappingSpace) Invalidate(ar usermem.AddrRange, opts memmap.InvalidateOpts) {
}

func anonInode(ctx context.Context) *fs.Inode {
	return fs.NewInode(&SimpleFileInode{
		InodeSimpleAttributes: NewInodeSimpleAttributes(ctx, fs.FileOwnerFromContext(ctx), fs.FilePermissions{
			User: fs.PermMask{Read: true, Write: true},
		}, 0),
	}, fs.NewPseudoMountSource(), fs.StableAttr{
		Type:      fs.Anonymous,
		BlockSize: usermem.PageSize,
	})
}

func pagesOf(bs ...byte) []byte {
	buf := make([]byte, 0, len(bs)*usermem.PageSize)
	for _, b := range bs {
		buf = append(buf, bytes.Repeat([]byte{b}, usermem.PageSize)...)
	}
	return buf
}

func TestRead(t *testing.T) {
	ctx := contexttest.Context(t)

	// Construct a 3-page file.
	buf := pagesOf('a', 'b', 'c')
	file := fs.NewFile(ctx, fs.NewDirent(anonInode(ctx), "anon"), fs.FileFlags{}, nil)
	uattr := fs.UnstableAttr{
		Size: int64(len(buf)),
	}
	iops := NewCachingInodeOperations(ctx, newSliceBackingFile(buf), uattr, false /*forcePageCache*/)
	defer iops.Release()

	// Expect the cache to be initially empty.
	if cached := iops.cache.Span(); cached != 0 {
		t.Errorf("Span got %d, want 0", cached)
	}

	// Create a memory mapping of the second page (as CachingInodeOperations
	// expects to only cache mapped pages), then call Translate to force it to
	// be cached.
	var ms noopMappingSpace
	ar := usermem.AddrRange{usermem.PageSize, 2 * usermem.PageSize}
	if err := iops.AddMapping(ctx, ms, ar, usermem.PageSize, true); err != nil {
		t.Fatalf("AddMapping got %v, want nil", err)
	}
	mr := memmap.MappableRange{usermem.PageSize, 2 * usermem.PageSize}
	if _, err := iops.Translate(ctx, mr, mr, usermem.Read); err != nil {
		t.Fatalf("Translate got %v, want nil", err)
	}
	if cached := iops.cache.Span(); cached != usermem.PageSize {
		t.Errorf("SpanRange got %d, want %d", cached, usermem.PageSize)
	}

	// Try to read 4 pages. The first and third pages should be read directly
	// from the "file", the second page should be read from the cache, and only
	// 3 pages (the size of the file) should be readable.
	rbuf := make([]byte, 4*usermem.PageSize)
	dst := usermem.BytesIOSequence(rbuf)
	n, err := iops.Read(ctx, file, dst, 0)
	if n != 3*usermem.PageSize || (err != nil && err != io.EOF) {
		t.Fatalf("Read got (%d, %v), want (%d, nil or EOF)", n, err, 3*usermem.PageSize)
	}
	rbuf = rbuf[:3*usermem.PageSize]

	// Did we get the bytes we expect?
	if !bytes.Equal(rbuf, buf) {
		t.Errorf("Read back bytes %v, want %v", rbuf, buf)
	}

	// Delete the memory mapping and expect it to cause the cached page to be
	// uncached.
	iops.RemoveMapping(ctx, ms, ar, usermem.PageSize, true)
	if cached := iops.cache.Span(); cached != 0 {
		t.Fatalf("Span got %d, want 0", cached)
	}
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
	iops := NewCachingInodeOperations(ctx, newSliceBackingFile(buf), uattr, false /*forcePageCache*/)
	defer iops.Release()

	// Expect the cache to be initially empty.
	if cached := iops.cache.Span(); cached != 0 {
		t.Errorf("Span got %d, want 0", cached)
	}

	// Create a memory mapping of the second and third pages (as
	// CachingInodeOperations expects to only cache mapped pages), then call
	// Translate to force them to be cached.
	var ms noopMappingSpace
	ar := usermem.AddrRange{usermem.PageSize, 3 * usermem.PageSize}
	if err := iops.AddMapping(ctx, ms, ar, usermem.PageSize, true); err != nil {
		t.Fatalf("AddMapping got %v, want nil", err)
	}
	defer iops.RemoveMapping(ctx, ms, ar, usermem.PageSize, true)
	mr := memmap.MappableRange{usermem.PageSize, 3 * usermem.PageSize}
	if _, err := iops.Translate(ctx, mr, mr, usermem.Read); err != nil {
		t.Fatalf("Translate got %v, want nil", err)
	}
	if cached := iops.cache.Span(); cached != 2*usermem.PageSize {
		t.Errorf("SpanRange got %d, want %d", cached, 2*usermem.PageSize)
	}

	// Write to the first 2 pages.
	wbuf := pagesOf('e', 'f')
	src := usermem.BytesIOSequence(wbuf)
	n, err := iops.Write(ctx, src, 0)
	if n != 2*usermem.PageSize || err != nil {
		t.Fatalf("Write got (%d, %v), want (%d, nil)", n, err, 2*usermem.PageSize)
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
	copy(want[usermem.PageSize:], pagesOf('f'))
	if !bytes.Equal(buf, want) {
		t.Errorf("File contents are %v, want %v", buf, want)
	}
}
