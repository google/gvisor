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

package portforward

import (
	"bytes"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
)

// chunkConn is a proxyConn that returns src from a single Read and accepts at
// most maxWrite bytes per Write.
type chunkConn struct {
	src      []byte
	maxWrite int
	written  bytes.Buffer
	writes   int
}

func (c *chunkConn) Name() string { return "chunkConn" }

func (c *chunkConn) Read(_ context.Context, buf []byte, _ <-chan struct{}) (int, error) {
	if len(c.src) == 0 {
		return 0, io.EOF
	}
	n := copy(buf, c.src)
	c.src = c.src[n:]
	return n, nil
}

func (c *chunkConn) Write(_ context.Context, buf []byte, _ <-chan struct{}) (int, error) {
	c.writes++
	n := min(len(buf), c.maxWrite)
	c.written.Write(buf[:n])
	return n, nil
}

func (c *chunkConn) Close(context.Context) {}

func TestDoCopyPartialWrites(t *testing.T) {
	ctx := context.Background()
	want := []byte("the quick brown fox jumps over the lazy dog")
	src := &chunkConn{src: want}
	dst := &chunkConn{maxWrite: 5}
	buf := make([]byte, 1024)

	if err := doCopy(ctx, dst, src, buf, make(chan struct{})); err != nil {
		t.Fatalf("doCopy failed: %v", err)
	}
	if got := dst.written.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("destination got %q, want %q", got, want)
	}
	if wantWrites := (len(want) + 4) / 5; dst.writes != wantWrites {
		t.Errorf("destination got %d writes, want %d", dst.writes, wantWrites)
	}
}

func TestDoCopyZeroLengthWrite(t *testing.T) {
	ctx := context.Background()
	src := &chunkConn{src: []byte("data")}
	dst := &chunkConn{maxWrite: 0}
	buf := make([]byte, 1024)

	err := doCopy(ctx, dst, src, buf, make(chan struct{}))
	if err == nil {
		t.Fatalf("doCopy succeeded, want error for a write that makes no progress")
	}
	if dst.writes != 1 {
		t.Errorf("destination got %d writes, want 1", dst.writes)
	}
}

func TestDoCopyReadError(t *testing.T) {
	ctx := context.Background()
	src := &chunkConn{}
	dst := &chunkConn{maxWrite: 1024}
	buf := make([]byte, 1024)

	if err := doCopy(ctx, dst, src, buf, make(chan struct{})); err == nil {
		t.Fatalf("doCopy succeeded, want error when the source is at EOF")
	}
	if dst.writes != 0 {
		t.Errorf("destination got %d writes, want 0", dst.writes)
	}
}
