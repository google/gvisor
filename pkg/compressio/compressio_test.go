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

package compressio

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"time"
)

type harness interface {
	Errorf(format string, v ...any)
	Fatalf(format string, v ...any)
	Logf(format string, v ...any)
}

func initTest(t harness, size int) []byte {
	// Set number of processes to number of CPUs.
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Construct synthetic data. We do this by encoding random data with
	// base64. This gives a high level of entropy, but still quite a bit of
	// structure, to give reasonable compression ratios (~75%).
	var buf bytes.Buffer
	bufW := base64.NewEncoder(base64.RawStdEncoding, &buf)
	bufR := rand.New(rand.NewSource(0))
	if _, err := io.CopyN(bufW, bufR, int64(size)); err != nil {
		t.Fatalf("unable to seed random data: %v", err)
	}
	return buf.Bytes()
}

type testOpts struct {
	Name        string
	Data        []byte
	NewWriter   func(*bytes.Buffer) (io.WriteCloser, error)
	NewReader   func(*bytes.Buffer) (io.Reader, error)
	PreWrite    func()
	PostWrite   func()
	PreRead     func()
	PostRead    func()
	WriteIters  int
	ReadIters   int
	CorruptData bool
}

func doTest(t harness, opts testOpts) {
	// Compress.
	var compressed bytes.Buffer
	compressionStartTime := time.Now()
	if opts.PreWrite != nil {
		opts.PreWrite()
	}
	if opts.WriteIters <= 0 {
		opts.WriteIters = 1
	}
	for i := 0; i < opts.WriteIters; i++ {
		compressed.Reset()
		w, err := opts.NewWriter(&compressed)
		if err != nil {
			t.Errorf("%s: NewWriter got err %v, expected nil", opts.Name, err)
		}
		if _, err := io.Copy(w, bytes.NewBuffer(opts.Data)); err != nil {
			t.Errorf("%s: compress got err %v, expected nil", opts.Name, err)
			return
		}
		if err := w.Close(); err != nil {
			t.Errorf("%s: got err %v, expected nil", opts.Name, err)
			return
		}
	}
	if opts.PostWrite != nil {
		opts.PostWrite()
	}
	compressionTime := time.Since(compressionStartTime)
	compressionRatio := float32(compressed.Len()) / float32(len(opts.Data))

	if compressed.Len() == 0 {
		// Data can't be corrupted if there is no data.
		opts.CorruptData = false
	}

	// Decompress.
	var decompressed bytes.Buffer
	decompressionStartTime := time.Now()
	if opts.PreRead != nil {
		opts.PreRead()
	}
	if opts.ReadIters <= 0 {
		opts.ReadIters = 1
	}
	if opts.CorruptData {
		b := compressed.Bytes()
		b[rand.Intn(len(b))]++
	}
	for i := 0; i < opts.ReadIters; i++ {
		decompressed.Reset()
		r, err := opts.NewReader(bytes.NewBuffer(compressed.Bytes()))
		if err != nil {
			if opts.CorruptData {
				continue
			}
			t.Errorf("%s: NewReader got err %v, expected nil", opts.Name, err)
			return
		}
		if _, err := io.Copy(&decompressed, r); (err != nil) != opts.CorruptData {
			t.Errorf("%s: decompress got err %v unexpectedly", opts.Name, err)
			return
		}
	}
	if opts.PostRead != nil {
		opts.PostRead()
	}
	decompressionTime := time.Since(decompressionStartTime)

	if opts.CorruptData {
		return
	}

	// Verify.
	if decompressed.Len() != len(opts.Data) {
		t.Errorf("%s: got %d bytes, expected %d", opts.Name, decompressed.Len(), len(opts.Data))
	}
	if !bytes.Equal(opts.Data, decompressed.Bytes()) {
		t.Errorf("%s: got mismatch, expected match", opts.Name)
		if len(opts.Data) < 32 { // Don't flood the logs.
			t.Errorf("got %v, expected %v", decompressed.Bytes(), opts.Data)
		}
	}

	t.Logf("%s: compression time %v, ratio %2.2f, decompression time %v",
		opts.Name, compressionTime, compressionRatio, decompressionTime)
}

var hashKey = []byte("01234567890123456789012345678901")

func TestCompress(t *testing.T) {
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
							return NewWriter(b, key, blockSize, flate.BestSpeed)
						},
						NewReader: func(b *bytes.Buffer) (io.Reader, error) {
							return NewReader(io.NopCloser(b), key)
						},
						CorruptData: corruptData,
					})
				}
			}
		}

		// Do the vanilla test.
		doTest(t, testOpts{
			Name: fmt.Sprintf("len(data)=%d, vanilla flate", len(data)),
			Data: data,
			NewWriter: func(b *bytes.Buffer) (io.WriteCloser, error) {
				return flate.NewWriter(b, flate.BestSpeed)
			},
			NewReader: func(b *bytes.Buffer) (io.Reader, error) {
				return flate.NewReader(b), nil
			},
		})
	}
}

const (
	benchDataSize = 600 * 1024 * 1024
)

func benchmark(b *testing.B, compression bool, write bool, hash bool, blockSize uint32) {
	b.StopTimer()
	b.SetBytes(benchDataSize)
	data := initTest(b, benchDataSize)
	key := hashKey
	if !hash {
		key = nil
	}
	opts := testOpts{
		Name: fmt.Sprintf("compression=%t, write=%t, hash=%t, len(data)=%d, blockSize=%d", compression, write, hash, len(data), blockSize),
		Data: data,
	}
	if compression {
		opts.NewWriter = func(b *bytes.Buffer) (io.WriteCloser, error) {
			return NewWriter(b, key, blockSize, flate.BestSpeed)
		}
		opts.NewReader = func(b *bytes.Buffer) (io.Reader, error) {
			return NewReader(io.NopCloser(b), key)
		}
	} else {
		opts.NewWriter = func(b *bytes.Buffer) (io.WriteCloser, error) {
			return NewSimpleWriter(b, key, blockSize), nil
		}
		opts.NewReader = func(b *bytes.Buffer) (io.Reader, error) {
			return NewSimpleReader(io.NopCloser(b), key), nil
		}
	}
	if write {
		opts.PreWrite = b.StartTimer
		opts.PostWrite = b.StopTimer
		opts.WriteIters = b.N
	} else {
		opts.PreRead = b.StartTimer
		opts.PostRead = b.StopTimer
		opts.ReadIters = b.N
	}
	doTest(b, opts)
}

func benchmarkName(compression bool, write bool, hash bool, blockSize uint32) string {
	var sb strings.Builder
	if compression {
		sb.WriteString("Compress")
	} else {
		sb.WriteString("NoCompress")
	}
	if write {
		sb.WriteString("Write")
	} else {
		sb.WriteString("Read")
	}
	if hash {
		sb.WriteString("Hash")
	} else {
		sb.WriteString("NoHash")
	}
	sb.WriteString(fmt.Sprintf("%dKbBlock", blockSize/1024))
	return sb.String()
}

func BenchmarkLargeIO(b *testing.B) {
	for _, compress := range []bool{false, true} {
		for _, blockSize := range []uint32{64 * 1024, 1024 * 1024, 16 * 1024 * 1024} {
			for _, hash := range []bool{false, true} {
				for _, write := range []bool{false, true} {
					b.Run(benchmarkName(compress, write, hash, blockSize), func(b *testing.B) {
						benchmark(b, compress, write, hash, blockSize)
					})
				}
			}
		}
	}
}
