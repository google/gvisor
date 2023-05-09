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

package pipe

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func runTest(t *testing.T, sizeBytes int64, tester func(ctx context.Context, r, w *vfs.FileDescription)) {
	ctx := contexttest.Context(t)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vd := vfsObj.NewAnonVirtualDentry("pipe")
	defer vd.DecRef(ctx)

	vp := NewVFSPipe(false /* isNamed */, sizeBytes)
	r, w, err := vp.ReaderWriterPair(ctx, vd.Mount(), vd.Dentry(), 0)
	if err != nil {
		t.Fatalf("ReaderWriterPair failed: %v", err)
	}
	defer r.DecRef(ctx)
	defer w.DecRef(ctx)

	tester(ctx, r, w)
}

func TestPipeRW(t *testing.T) {
	runTest(t, 65536, func(ctx context.Context, r *vfs.FileDescription, w *vfs.FileDescription) {
		msg := []byte("here's some bytes")
		wantN := int64(len(msg))
		n, err := w.Write(ctx, usermem.BytesIOSequence(msg), vfs.WriteOptions{})
		if n != wantN || err != nil {
			t.Fatalf("Writev: got (%d, %v), wanted (%d, nil)", n, err, wantN)
		}

		buf := make([]byte, len(msg))
		n, err = r.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if n != wantN || err != nil || !bytes.Equal(buf, msg) {
			t.Fatalf("Readv: got (%d, %v) %q, wanted (%d, nil) %q", n, err, buf, wantN, msg)
		}
	})
}

func TestPipeReadBlock(t *testing.T) {
	runTest(t, 65536, func(ctx context.Context, r *vfs.FileDescription, w *vfs.FileDescription) {
		n, err := r.Read(ctx, usermem.BytesIOSequence(make([]byte, 1)), vfs.ReadOptions{})
		if n != 0 || err != linuxerr.ErrWouldBlock {
			t.Fatalf("Readv: got (%d, %v), wanted (0, %v)", n, err, linuxerr.ErrWouldBlock)
		}
	})
}

func TestPipeWriteBlock(t *testing.T) {
	const atomicIOBytes = 2
	const capacity = MinimumPipeSize

	runTest(t, capacity, func(ctx context.Context, r *vfs.FileDescription, w *vfs.FileDescription) {
		msg := make([]byte, capacity+1)
		n, err := w.Write(ctx, usermem.BytesIOSequence(msg), vfs.WriteOptions{})
		if wantN, wantErr := int64(capacity), linuxerr.ErrWouldBlock; n != wantN || err != wantErr {
			t.Fatalf("Writev: got (%d, %v), wanted (%d, %v)", n, err, wantN, wantErr)
		}
	})
}

func TestPipeWriteUntilEnd(t *testing.T) {
	const atomicIOBytes = 2
	runTest(t, atomicIOBytes, func(ctx context.Context, r *vfs.FileDescription, w *vfs.FileDescription) {
		msg := []byte("here's some bytes")

		wDone := make(chan struct{}, 0)
		rDone := make(chan struct{}, 0)
		defer func() {
			// Signal the reader to stop and wait until it does so.
			close(wDone)
			<-rDone
		}()

		go func() {
			defer close(rDone)
			// Read from r until done is closed.
			ctx := contexttest.Context(t)
			buf := make([]byte, len(msg)+1)
			dst := usermem.BytesIOSequence(buf)
			e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
			r.EventRegister(&e)
			defer r.EventUnregister(&e)
			for {
				n, err := r.Read(ctx, dst, vfs.ReadOptions{})
				dst = dst.DropFirst64(n)
				if err == linuxerr.ErrWouldBlock {
					select {
					case <-ch:
						continue
					case <-wDone:
						// We expect to have 1 byte left in dst since len(buf) ==
						// len(msg)+1.
						if dst.NumBytes() != 1 || !bytes.Equal(buf[:len(msg)], msg) {
							t.Errorf("Reader: got %q (%d bytes remaining), wanted %q", buf, dst.NumBytes(), msg)
						}
						return
					}
				}
				if err != nil {
					t.Errorf("Readv: got unexpected error %v", err)
					return
				}
			}
		}()

		src := usermem.BytesIOSequence(msg)
		e, ch := waiter.NewChannelEntry(waiter.WritableEvents)
		w.EventRegister(&e)
		defer w.EventUnregister(&e)
		for src.NumBytes() != 0 {
			n, err := w.Write(ctx, src, vfs.WriteOptions{})
			src = src.DropFirst64(n)
			if err == linuxerr.ErrWouldBlock {
				<-ch
				continue
			}
			if err != nil {
				t.Fatalf("Writev: got (%d, %v)", n, err)
			}
		}
	})
}
