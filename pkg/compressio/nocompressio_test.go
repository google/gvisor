// Copyright 2023 The gVisor Authors.
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

package compressio

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"
)

func TestNoCompress(t *testing.T) {
	rand.Seed(time.Now().Unix())

	var (
		data  = initTest(t, 10*1024*1024)
		data0 = data[:0]
		data1 = data[:1]
		data2 = data[:11]
		data3 = data[:16]
		data4 = data[:]
	)

	for _, data := range [][]byte{data0, data1, data2, data3, data4} {
		for _, blockSize := range []uint32{1, 4, 1024, 4 * 1024, 16 * 1024} {
			// Skip annoying tests; they just take too long.
			if blockSize <= 16 && len(data) > 16 {
				continue
			}

			for _, key := range [][]byte{nil, hashKey} {
				for _, corruptData := range []bool{false, true} {
					if key == nil && corruptData {
						// No need to test corrupt data
						// case when not doing hashing.
						continue
					}
					// Do the compress test.
					doTest(t, testOpts{
						Name: fmt.Sprintf("len(data)=%d, blockSize=%d, key=%s, corruptData=%v", len(data), blockSize, string(key), corruptData),
						Data: data,
						NewWriter: func(b *bytes.Buffer) (io.WriteCloser, error) {
							return NewSimpleWriter(b, key), nil
						},
						NewReader: func(b *bytes.Buffer) (io.Reader, error) {
							return NewSimpleReader(b, key), nil
						},
						CorruptData: corruptData,
					})
				}
			}
		}
	}
}

// The following benchmarks aims to be representative of how the wire
// package writes to the image. In practice, wire package only calls Write
// with a single byte at a time. Because all types boil down to wire.Uint
// whose implementation invokes Write with one byte at a time.

func BenchmarkTinyIO(b *testing.B) {
	// Use the same chunk size as the statefile package.
	const blockSize = 1024 * 1024
	for _, key := range [][]byte{nil, hashKey} {
		b.Run(benchmarkName(false, true, key != nil, blockSize), func(b *testing.B) {
			benchmarkNoCompress1ByteWrite(b, key, blockSize)
		})
	}
}

func benchmarkNoCompress1ByteWrite(b *testing.B, key []byte, blockSize uint32) {
	var (
		buf [1]byte
		out bytes.Buffer
	)
	w := NewSimpleWriter(&out, key)
	for i := 0; i < b.N; i++ {
		w.Write(buf[:])
	}
	w.Close()
}
