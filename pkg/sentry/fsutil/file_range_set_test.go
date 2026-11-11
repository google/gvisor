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

package fsutil

import (
	"io"
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

func TestFileRangeSetFillInitializedPrefix(t *testing.T) {
	page := uint64(hostarch.PageSize)
	for _, tc := range []struct {
		name       string
		fileSize   uint64
		readBytes  uint64
		readErr    error
		wantLength uint64
		wantErr    error
	}{
		{name: "EOF tail", fileSize: 2 * page, readBytes: 17, readErr: io.EOF, wantLength: page, wantErr: io.EOF},
		{name: "file size tail", fileSize: 17, readBytes: 17, wantLength: page, wantErr: io.EOF},
		{name: "partial second page", fileSize: 2 * page, readBytes: page + 17, readErr: io.EOF, wantLength: 2 * page},
		{name: "page boundary EOF", fileSize: 2 * page, readBytes: page, readErr: io.EOF, wantLength: page, wantErr: io.EOF},
		{name: "error discards partial page", fileSize: 2 * page, readBytes: page + 17, readErr: io.ErrUnexpectedEOF, wantLength: page, wantErr: io.ErrUnexpectedEOF},
		{name: "no progress", fileSize: 2 * page, wantErr: io.ErrNoProgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := memutil.CreateMemFD("fill-initializer-test", 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "fill-initializer-test")
			mf, err := pgalloc.NewMemoryFile(file, pgalloc.MemoryFileOpts{DisableMemoryAccounting: true})
			if err != nil {
				file.Close()
				t.Fatal(err)
			}
			t.Cleanup(mf.Destroy)
			var set FileRangeSet
			t.Cleanup(func() { set.DropAll(mf) })
			mr := memmap.MappableRange{Start: 0, End: 2 * page}
			_, err = set.Fill(context.Background(), mr, mr, tc.fileSize, mf, pgalloc.AllocOpts{
				Mode: pgalloc.AllocateAndWritePopulate,
			}, func(_ context.Context, dsts safemem.BlockSeq, _ uint64) (uint64, error) {
				// A source may modify bytes beyond its reported prefix. EOF
				// padding must initialize those bytes explicitly.
				for it := dsts; !it.IsEmpty(); it = it.Tail() {
					bs := it.Head().ToSlice()
					for i := range bs {
						bs[i] = 0xa5
					}
				}
				return tc.readBytes, tc.readErr
			})
			if err != tc.wantErr {
				t.Fatalf("Fill error = %v, want %v", err, tc.wantErr)
			}
			seg := set.FirstSegment()
			if tc.wantLength == 0 {
				if seg.Ok() {
					t.Fatal("Fill published a page without an initialized prefix")
				}
				return
			}
			if !seg.Ok() || seg.Range().Length() != tc.wantLength || seg.NextSegment().Ok() {
				t.Fatalf("unexpected initialized coverage: %v", set.ExportSlice())
			}
			blocks, err := mf.MapInternal(seg.FileRange(), hostarch.Read)
			if err != nil {
				t.Fatal(err)
			}
			var off uint64
			for ; !blocks.IsEmpty(); blocks = blocks.Tail() {
				for _, got := range blocks.Head().ToSlice() {
					want := byte(0xa5)
					if off >= tc.readBytes {
						want = 0
					}
					if got != want {
						t.Fatalf("byte %d = %#x, want %#x", off, got, want)
					}
					off++
				}
			}
		})
	}
}
