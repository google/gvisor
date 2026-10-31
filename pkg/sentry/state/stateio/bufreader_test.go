// Copyright 2025 The gVisor Authors.
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

package stateio

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rand"
)

// bytesBufferWriter wraps bytes.Buffer to hide bytes.Buffer.ReadFrom,
// ensuring that io.CopyBuffer performs a buffered copy.
type bytesBufferWriter struct {
	b bytes.Buffer
}

// Write implements io.Writer.Write.
func (w *bytesBufferWriter) Write(src []byte) (int, error) {
	return w.b.Write(src)
}

func TestBufReader(t *testing.T) {
	const dataLen = 32 << 10 // 32 KiB
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	for _, maxReadBytes := range []int{dataLen / 64, dataLen / 32, dataLen / 2, dataLen, dataLen * 2} {
		for _, maxParallel := range []int{1, 2, 32, 64} {
			for _, maxBufSize := range []int{0, maxReadBytes - 1, 2*maxReadBytes + 1} {
				for _, readBytes := range []int{maxReadBytes - 2, maxReadBytes - 1, maxReadBytes, maxReadBytes + 1, maxReadBytes * maxParallel, maxReadBytes*maxParallel + 1} {
					t.Run(fmt.Sprintf("MaxReadBytes%d_MaxParallel%d_MaxBufSize%d_ReadBytes%d", maxReadBytes, maxParallel, maxBufSize, readBytes), func(t *testing.T) {
						r, err := NewBufReader(NewIOReader(bytes.NewReader(data), uint64(maxReadBytes), 1 /* maxRanges */, maxParallel), maxBufSize)
						if err != nil {
							t.Fatalf("NewBufReader failed: %v", err)
						}
						defer r.Close()
						var w bytesBufferWriter
						copyBuf := make([]byte, readBytes)
						n, err := io.CopyBuffer(&w, r, copyBuf)
						if n != dataLen || err != nil {
							t.Fatalf("io.CopyBuffer: got (%d, %v), want (%d, nil)", n, err, dataLen)
						}
						if !bytes.Equal(data, w.b.Bytes()) {
							t.Errorf("Bytes differ")
						}
					})
				}
			}
		}
	}
}

func TestBufReaderFDReader(t *testing.T) {
	// The file length is not a multiple of the chunk length, so the last read
	// is short and the reads after it are past the end of the file.
	const (
		maxReadBytes = 64 << 10
		dataLen      = 5*maxReadBytes + 123
	)
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	for _, maxParallel := range []int{1, 4, 8} {
		for _, maxBufSize := range []int{maxReadBytes, 4 * maxReadBytes, 2 * dataLen} {
			t.Run(fmt.Sprintf("MaxParallel%d_MaxBufSize%d", maxParallel, maxBufSize), func(t *testing.T) {
				fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatalf("Open failed: %v", err)
				}
				r, err := NewBufReader(NewFDReader(int32(fd), maxReadBytes, 1 /* maxRanges */, maxParallel), maxBufSize)
				if err != nil {
					t.Fatalf("NewBufReader failed: %v", err)
				}
				got, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("ReadAll failed: %v", err)
				}
				if !bytes.Equal(got, data) {
					t.Errorf("got %d bytes that differ from the %d bytes in the file", len(got), dataLen)
				}
				if n, err := r.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Errorf("Read after EOF: got (%d, %v), want (0, EOF)", n, err)
				}
				if err := r.Close(); err != nil {
					t.Errorf("Close failed: %v", err)
				}
			})
		}
	}
}
