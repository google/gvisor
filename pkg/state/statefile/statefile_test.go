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

package statefile

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"io"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/compressio"
)

func randomKey() ([]byte, error) {
	r := make([]byte, base64.RawStdEncoding.DecodedLen(keySize))
	if _, err := io.ReadFull(crand.Reader, r); err != nil {
		return nil, err
	}
	key := make([]byte, keySize)
	base64.RawStdEncoding.Encode(key, r)
	return key, nil
}

type testCase struct {
	name     string
	data     []byte
	metadata map[string]string
}

func TestStatefile(t *testing.T) {
	rand.Seed(time.Now().Unix())

	cases := []testCase{
		// Various data sizes.
		{"nil", nil, nil},
		{"empty", []byte(""), nil},
		{"some", []byte("_"), nil},
		{"one", []byte("0"), nil},
		{"two", []byte("01"), nil},
		{"three", []byte("012"), nil},
		{"four", []byte("0123"), nil},
		{"five", []byte("01234"), nil},
		{"six", []byte("012356"), nil},
		{"seven", []byte("0123567"), nil},
		{"eight", []byte("01235678"), nil},

		// Make sure we have one longer than the hash length.
		{"longer than hash", []byte("012356asdjflkasjlk3jlk23j4lkjaso0d789f0aujw3lkjlkxsdf78asdful2kj3ljka78"), nil},

		// Make sure we have one longer than the chunk size.
		{"chunks", make([]byte, 3*compressionChunkSize), nil},
		{"large", make([]byte, 30*compressionChunkSize), nil},

		// Different metadata.
		{"one metadata", []byte("data"), map[string]string{"foo": "bar"}},
		{"two metadata", []byte("data"), map[string]string{"foo": "bar", "one": "two"}},
	}

	for _, c := range cases {
		// Generate a key.
		integrityKey, err := randomKey()
		if err != nil {
			t.Errorf("can't generate key: got %v, excepted nil", err)
			continue
		}

		t.Run(c.name, func(t *testing.T) {
			for _, key := range [][]byte{nil, integrityKey} {
				t.Run("key="+string(key), func(t *testing.T) {
					// Encoding happens via a buffer.
					var bufEncoded bytes.Buffer
					var bufDecoded bytes.Buffer

					// Do all the writing.
					w, err := NewWriter(&bufEncoded, key, c.metadata)
					if err != nil {
						t.Fatalf("error creating writer: got %v, expected nil", err)
					}
					if _, err := io.Copy(w, bytes.NewBuffer(c.data)); err != nil {
						t.Fatalf("error during write: got %v, expected nil", err)
					}

					// Finish the sum.
					if err := w.Close(); err != nil {
						t.Fatalf("error during close: got %v, expected nil", err)
					}

					t.Logf("original data: %d bytes, encoded: %d bytes.",
						len(c.data), len(bufEncoded.Bytes()))

					// Do all the reading.
					r, metadata, err := NewReader(bytes.NewReader(bufEncoded.Bytes()), key)
					if err != nil {
						t.Fatalf("error creating reader: got %v, expected nil", err)
					}
					if _, err := io.Copy(&bufDecoded, r); err != nil {
						t.Fatalf("error during read: got %v, expected nil", err)
					}

					// Check that the data matches.
					if !bytes.Equal(c.data, bufDecoded.Bytes()) {
						t.Fatalf("data didn't match (%d vs %d bytes)", len(bufDecoded.Bytes()), len(c.data))
					}

					// Check that the metadata matches.
					for k, v := range c.metadata {
						nv, ok := metadata[k]
						if !ok {
							t.Fatalf("missing metadata: %s", k)
						}
						if v != nv {
							t.Fatalf("mismatched metdata for %s: got %s, expected %s", k, nv, v)
						}
					}

					// Change the data and verify that it fails.
					if key != nil {
						b := append([]byte(nil), bufEncoded.Bytes()...)
						b[rand.Intn(len(b))]++
						bufDecoded.Reset()
						r, _, err = NewReader(bytes.NewReader(b), key)
						if err == nil {
							_, err = io.Copy(&bufDecoded, r)
						}
						if err == nil {
							t.Error("got no error: expected error on data corruption")
						}
					}

					// Change the key and verify that it fails.
					newKey := integrityKey
					if len(key) > 0 {
						newKey = append([]byte{}, key...)
						newKey[rand.Intn(len(newKey))]++
					}
					bufDecoded.Reset()
					r, _, err = NewReader(bytes.NewReader(bufEncoded.Bytes()), newKey)
					if err == nil {
						_, err = io.Copy(&bufDecoded, r)
					}
					if err != compressio.ErrHashMismatch {
						t.Errorf("got error: %v, expected ErrHashMismatch on key mismatch", err)
					}
				})
			}
		})
	}
}

const benchmarkDataSize = 100 * 1024 * 1024

func benchmark(b *testing.B, size int, write bool, compressible bool) {
	b.StopTimer()
	b.SetBytes(benchmarkDataSize)

	// Generate source data.
	var source []byte
	if compressible {
		// For compressible data, we use essentially all zeros.
		source = make([]byte, benchmarkDataSize)
	} else {
		// For non-compressible data, we use random base64 data (to
		// make it marginally compressible, a ratio of 75%).
		var sourceBuf bytes.Buffer
		bufW := base64.NewEncoder(base64.RawStdEncoding, &sourceBuf)
		bufR := rand.New(rand.NewSource(0))
		if _, err := io.CopyN(bufW, bufR, benchmarkDataSize); err != nil {
			b.Fatalf("unable to seed random data: %v", err)
		}
		source = sourceBuf.Bytes()
	}

	// Generate a random key for integrity check.
	key, err := randomKey()
	if err != nil {
		b.Fatalf("error generating key: %v", err)
	}

	// Define our benchmark functions. Prior to running the readState
	// function here, you must execute the writeState function at least
	// once (done below).
	var stateBuf bytes.Buffer
	writeState := func() {
		stateBuf.Reset()
		w, err := NewWriter(&stateBuf, key, nil)
		if err != nil {
			b.Fatalf("error creating writer: %v", err)
		}
		for done := 0; done < len(source); {
			chunk := size // limit size.
			if done+chunk > len(source) {
				chunk = len(source) - done
			}
			n, err := w.Write(source[done : done+chunk])
			done += n
			if n == 0 && err != nil {
				b.Fatalf("error during write: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			b.Fatalf("error closing writer: %v", err)
		}
	}
	readState := func() {
		tmpBuf := bytes.NewBuffer(stateBuf.Bytes())
		r, _, err := NewReader(tmpBuf, key)
		if err != nil {
			b.Fatalf("error creating reader: %v", err)
		}
		for done := 0; done < len(source); {
			chunk := size // limit size.
			if done+chunk > len(source) {
				chunk = len(source) - done
			}
			n, err := r.Read(source[done : done+chunk])
			done += n
			if n == 0 && err != nil {
				b.Fatalf("error during read: %v", err)
			}
		}
	}
	// Generate the state once without timing to ensure that buffers have
	// been appropriately allocated.
	writeState()
	if write {
		b.StartTimer()
		for i := 0; i < b.N; i++ {
			writeState()
		}
		b.StopTimer()
	} else {
		b.StartTimer()
		for i := 0; i < b.N; i++ {
			readState()
		}
		b.StopTimer()
	}
}

func BenchmarkWrite4KCompressible(b *testing.B) {
	benchmark(b, 4096, true, true)
}

func BenchmarkWrite4KNoncompressible(b *testing.B) {
	benchmark(b, 4096, true, false)
}

func BenchmarkWrite1MCompressible(b *testing.B) {
	benchmark(b, 1024*1024, true, true)
}

func BenchmarkWrite1MNoncompressible(b *testing.B) {
	benchmark(b, 1024*1024, true, false)
}

func BenchmarkRead4KCompressible(b *testing.B) {
	benchmark(b, 4096, false, true)
}

func BenchmarkRead4KNoncompressible(b *testing.B) {
	benchmark(b, 4096, false, false)
}

func BenchmarkRead1MCompressible(b *testing.B) {
	benchmark(b, 1024*1024, false, true)
}

func BenchmarkRead1MNoncompressible(b *testing.B) {
	benchmark(b, 1024*1024, false, false)
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
