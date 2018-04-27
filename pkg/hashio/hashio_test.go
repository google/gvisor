// Copyright 2018 Google Inc.
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

package hashio

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"testing"
)

var testKey = []byte("01234567890123456789012345678901")

func runTest(c []byte, fn func(enc *bytes.Buffer), iters int) error {
	// Encoding happens via a buffer.
	var (
		enc bytes.Buffer
		dec bytes.Buffer
	)

	for i := 0; i < iters; i++ {
		enc.Reset()
		w := NewWriter(&enc, hmac.New(sha256.New, testKey))
		if _, err := io.Copy(w, bytes.NewBuffer(c)); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}

	fn(&enc)

	for i := 0; i < iters; i++ {
		dec.Reset()
		r := NewReader(bytes.NewReader(enc.Bytes()), hmac.New(sha256.New, testKey))
		if _, err := io.Copy(&dec, r); err != nil {
			return err
		}
	}

	// Check that the data matches; this should never fail.
	if !bytes.Equal(c, dec.Bytes()) {
		panic(fmt.Sprintf("data didn't match: got %v, expected %v", dec.Bytes(), c))
	}

	return nil
}

func TestTable(t *testing.T) {
	cases := [][]byte{
		// Various data sizes.
		nil,
		[]byte(""),
		[]byte("_"),
		[]byte("0"),
		[]byte("01"),
		[]byte("012"),
		[]byte("0123"),
		[]byte("01234"),
		[]byte("012356"),
		[]byte("0123567"),
		[]byte("01235678"),

		// Make sure we have one longer than the hash length.
		[]byte("012356asdjflkasjlk3jlk23j4lkjaso0d789f0aujw3lkjlkxsdf78asdful2kj3ljka78"),

		// Make sure we have one longer than the segment size.
		make([]byte, 3*SegmentSize),
		make([]byte, 3*SegmentSize-1),
		make([]byte, 3*SegmentSize+1),
		make([]byte, 3*SegmentSize-32),
		make([]byte, 3*SegmentSize+32),
		make([]byte, 30*SegmentSize),
	}

	for _, c := range cases {
		for _, flip := range []bool{false, true} {
			if len(c) == 0 && flip == true {
				continue
			}

			// Log the case.
			t.Logf("case: len=%d flip=%v", len(c), flip)

			if err := runTest(c, func(enc *bytes.Buffer) {
				if flip {
					corrupted := rand.Intn(enc.Len())
					enc.Bytes()[corrupted]++
				}
			}, 1); err != nil {
				if !flip || err != ErrHashMismatch {
					t.Errorf("error during read: got %v, expected nil", err)
				}
				continue
			} else if flip {
				t.Errorf("failed to detect ErrHashMismatch on corrupted data!")
				continue
			}
		}
	}
}

const benchBytes = 10 * 1024 * 1024 // 10 MB.

func BenchmarkWrite(b *testing.B) {
	b.StopTimer()
	x := make([]byte, benchBytes)
	b.SetBytes(benchBytes)
	b.StartTimer()
	if err := runTest(x, func(enc *bytes.Buffer) {
		b.StopTimer()
	}, b.N); err != nil {
		b.Errorf("benchmark failed: %v", err)
	}
}

func BenchmarkRead(b *testing.B) {
	b.StopTimer()
	x := make([]byte, benchBytes)
	b.SetBytes(benchBytes)
	if err := runTest(x, func(enc *bytes.Buffer) {
		b.StartTimer()
	}, b.N); err != nil {
		b.Errorf("benchmark failed: %v", err)
	}
}
