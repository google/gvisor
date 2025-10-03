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
	"testing"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/rand"
)

// bytesBufferReader wraps bytes.Buffer to hide bytes.Buffer.WriteTo, ensuring
// that io.CopyBuffer performs a buffered copy.
type bytesBufferReader struct {
	b bytes.Buffer
}

// Read implements io.Reader.Read.
func (r *bytesBufferReader) Read(src []byte) (int, error) {
	return r.b.Read(src)
}

func TestBufWriter(t *testing.T) {
	const dataLen = 32 << 10 // 32 KiB
	data := make([]byte, dataLen)
	_, _ = rand.Read(data)

	for _, maxWriteBytes := range []int{dataLen / 64, dataLen / 32, dataLen / 2, dataLen, dataLen * 2} {
		for _, maxParallel := range []int{1, 2, 32, 64} {
			for _, maxBufSize := range []int{0, maxWriteBytes - 1, 2*maxWriteBytes + 1} {
				for _, writeBytes := range []int{maxWriteBytes - 2, maxWriteBytes - 1, maxWriteBytes, maxWriteBytes + 1, maxWriteBytes * maxParallel, maxWriteBytes*maxParallel + 1} {
					t.Run(fmt.Sprintf("MaxWriteBytes%d_MaxParallel%d_MaxBufSize%d_WriteBytes%d", maxWriteBytes, maxParallel, maxBufSize, writeBytes), func(t *testing.T) {
						b := bytes.NewBuffer(make([]byte, 0, dataLen))
						w, err := NewBufWriter(NewIOWriter(b, uint64(maxWriteBytes), 1 /* maxRanges */, maxParallel), maxBufSize)
						if err != nil {
							t.Fatalf("NewBufWriter failed: %v", err)
						}
						cu := cleanup.Make(func() { w.Close() })
						defer cu.Clean()
						r := bytes.NewReader(data)
						copyBuf := make([]byte, writeBytes)
						n, err := io.CopyBuffer(w, r, copyBuf)
						if n != dataLen || err != nil {
							t.Fatalf("io.CopyBuffer: got (%d, %v), want (%d, nil)", n, err, dataLen)
						}
						err = w.Close()
						cu.Release()
						if err != nil {
							t.Fatalf("BufWriter.Close failed: %v", err)
						}
						if !bytes.Equal(data, b.Bytes()) {
							t.Errorf("Bytes differ")
						}
					})
				}
			}
		}
	}
}
