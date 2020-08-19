// Copyright 2020 The gVisor Authors.
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

package merkletree

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/usermem"
)

func TestLayout(t *testing.T) {
	testCases := []struct {
		dataSize            int64
		expectedLevelOffset []int64
	}{
		{
			dataSize:            100,
			expectedLevelOffset: []int64{0},
		},
		{
			dataSize:            1000000,
			expectedLevelOffset: []int64{0, 2 * usermem.PageSize, 3 * usermem.PageSize},
		},
		{
			dataSize:            4096 * int64(usermem.PageSize),
			expectedLevelOffset: []int64{0, 32 * usermem.PageSize, 33 * usermem.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			p := InitLayout(tc.dataSize)
			if p.blockSize != int64(usermem.PageSize) {
				t.Errorf("got blockSize %d, want %d", p.blockSize, usermem.PageSize)
			}
			if p.digestSize != sha256DigestSize {
				t.Errorf("got digestSize %d, want %d", p.digestSize, sha256DigestSize)
			}
			if p.numLevels() != len(tc.expectedLevelOffset) {
				t.Errorf("got levels %d, want %d", p.numLevels(), len(tc.expectedLevelOffset))
			}
			for i := 0; i < p.numLevels() && i < len(tc.expectedLevelOffset); i++ {
				if p.levelOffset[i] != tc.expectedLevelOffset[i] {
					t.Errorf("got levelStart[%d] %d, want %d", i, p.levelOffset[i], tc.expectedLevelOffset[i])
				}
			}
		})
	}
}

// bytesReadWriter is used to read from/write to/seek in a byte array. Unlike
// bytes.Buffer, it keeps the whole buffer during read so that it can be reused.
type bytesReadWriter struct {
	// bytes contains the underlying byte array.
	bytes []byte
	// readPos is the currently location for Read. Write always appends to
	// the end of the array.
	readPos int
}

func (brw *bytesReadWriter) Write(p []byte) (int, error) {
	brw.bytes = append(brw.bytes, p...)
	return len(p), nil
}

func (brw *bytesReadWriter) Read(p []byte) (int, error) {
	if brw.readPos >= len(brw.bytes) {
		return 0, io.EOF
	}
	bytesRead := copy(p, brw.bytes[brw.readPos:])
	brw.readPos += bytesRead
	if bytesRead < len(p) {
		return bytesRead, io.EOF
	}
	return bytesRead, nil
}

func (brw *bytesReadWriter) Seek(offset int64, whence int) (int64, error) {
	off := offset
	if whence == io.SeekCurrent {
		off += int64(brw.readPos)
	}
	if whence == io.SeekEnd {
		off += int64(len(brw.bytes))
	}
	if off < 0 {
		panic("seek with negative offset")
	}
	if off >= int64(len(brw.bytes)) {
		return 0, io.EOF
	}
	brw.readPos = int(off)
	return off, nil
}

func TestGenerate(t *testing.T) {
	// The input data has size dataSize. It starts with the data in startWith,
	// and all other bytes are zeroes.
	testCases := []struct {
		data         []byte
		expectedRoot []byte
	}{
		{
			data:         bytes.Repeat([]byte{0}, usermem.PageSize),
			expectedRoot: []byte{173, 127, 172, 178, 88, 111, 198, 233, 102, 192, 4, 215, 209, 209, 107, 2, 79, 88, 5, 255, 124, 180, 124, 122, 133, 218, 189, 139, 72, 137, 44, 167},
		},
		{
			data:         bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			expectedRoot: []byte{62, 93, 40, 92, 161, 241, 30, 223, 202, 99, 39, 2, 132, 113, 240, 139, 117, 99, 79, 243, 54, 18, 100, 184, 141, 121, 238, 46, 149, 202, 203, 132},
		},
		{
			data:         []byte{'a'},
			expectedRoot: []byte{52, 75, 204, 142, 172, 129, 37, 14, 145, 137, 103, 203, 11, 162, 209, 205, 30, 169, 213, 72, 20, 28, 243, 24, 242, 2, 92, 43, 169, 59, 110, 210},
		},
		{
			data:         bytes.Repeat([]byte{'a'}, usermem.PageSize),
			expectedRoot: []byte{201, 62, 238, 45, 13, 176, 47, 16, 172, 199, 70, 13, 149, 118, 225, 34, 220, 248, 205, 83, 196, 191, 141, 252, 174, 27, 62, 116, 235, 207, 255, 90},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d:%v", len(tc.data), tc.data[0]), func(t *testing.T) {
			var tree bytes.Buffer

			root, err := Generate(&bytesReadWriter{
				bytes:   tc.data,
				readPos: 0,
			}, int64(len(tc.data)), &tree, &tree)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if !bytes.Equal(root, tc.expectedRoot) {
				t.Errorf("Unexpected root")
			}
		})
	}
}

func TestVerify(t *testing.T) {
	// The input data has size dataSize. The portion to be verified ranges from
	// verifyStart with verifySize. A bit is flipped in outOfRangeByteIndex to
	// confirm that modifications outside the verification range does not cause
	// issue. And a bit is flipped in modifyByte to confirm that
	// modifications in the verification range is caught during verification.
	testCases := []struct {
		dataSize    int64
		verifyStart int64
		verifySize  int64
		// A byte in input data is modified during the test. If the
		// modified byte falls in verification range, Verify should
		// fail, otherwise Verify should still succeed.
		modifyByte    int64
		shouldSucceed bool
	}{
		// Verify range start outside the data range should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   usermem.PageSize,
			verifySize:    1,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Verifying range is valid if it starts inside data and ends
		// outside data range, in that case start to the end of data is
		// verified.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Invalid verify range (negative size) should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   1,
			verifySize:    -1,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// Invalid verify range (0 size) should fail.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			shouldSucceed: false,
		},
		// The test cases below use a block-aligned verify range.
		// Modifying a byte in the verified range should cause verify
		// to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    4 * usermem.PageSize,
			shouldSucceed: false,
		},
		// Modifying a byte before the verified range should not cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    4*usermem.PageSize - 1,
			shouldSucceed: true,
		},
		// Modifying a byte after the verified range should not cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4 * usermem.PageSize,
			verifySize:    usermem.PageSize,
			modifyByte:    5 * usermem.PageSize,
			shouldSucceed: true,
		},
		// The tests below use a non-block-aligned verify range.
		// Modifying a byte at strat of verify range should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    4*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte at the end of verify range should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    6*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte in the middle verified block should cause
		// verify to fail.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    5*usermem.PageSize + 123,
			shouldSucceed: false,
		},
		// Modifying a byte in the first block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    4*usermem.PageSize + 122,
			shouldSucceed: false,
		},
		// Modifying a byte in the last block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			dataSize:      8 * usermem.PageSize,
			verifyStart:   4*usermem.PageSize + 123,
			verifySize:    2 * usermem.PageSize,
			modifyByte:    6*usermem.PageSize + 124,
			shouldSucceed: false,
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.modifyByte), func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			// Generate random bytes in data.
			rand.Read(data)
			var tree bytesReadWriter

			root, err := Generate(&bytesReadWriter{
				bytes:   data,
				readPos: 0,
			}, int64(tc.dataSize), &tree, &tree)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			// Flip a bit in data and checks Verify results.
			var buf bytes.Buffer
			data[tc.modifyByte] ^= 1
			if tc.shouldSucceed {
				if err := Verify(&buf, bytes.NewReader(data), &tree, tc.dataSize, tc.verifyStart, tc.verifySize, root); err != nil && err != io.EOF {
					t.Errorf("Verification failed when expected to succeed: %v", err)
				}
				if int64(buf.Len()) != tc.verifySize || !bytes.Equal(data[tc.verifyStart:tc.verifyStart+tc.verifySize], buf.Bytes()) {
					t.Errorf("Incorrect output from Verify")
				}
			} else {
				if err := Verify(&buf, bytes.NewReader(data), &tree, tc.dataSize, tc.verifyStart, tc.verifySize, root); err == nil {
					t.Errorf("Verification succeeded when expected to fail")
				}
			}
		})
	}
}

func TestVerifyRandom(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	// Use a random dataSize.  Minimum size 2 so that we can pick a random
	// portion from it.
	dataSize := rand.Int63n(200*usermem.PageSize) + 2
	data := make([]byte, dataSize)
	// Generate random bytes in data.
	rand.Read(data)
	var tree bytesReadWriter

	root, err := Generate(&bytesReadWriter{
		bytes:   data,
		readPos: 0,
	}, int64(dataSize), &tree, &tree)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Pick a random portion of data.
	start := rand.Int63n(dataSize - 1)
	size := rand.Int63n(dataSize) + 1

	var buf bytes.Buffer
	// Checks that the random portion of data from the original data is
	// verified successfully.
	if err := Verify(&buf, bytes.NewReader(data), &tree, dataSize, start, size, root); err != nil && err != io.EOF {
		t.Errorf("Verification failed for correct data: %v", err)
	}
	if size > dataSize-start {
		size = dataSize - start
	}
	if int64(buf.Len()) != size || !bytes.Equal(data[start:start+size], buf.Bytes()) {
		t.Errorf("Incorrect output from Verify")
	}

	buf.Reset()
	// Flip a random bit in randPortion, and check that verification fails.
	randBytePos := rand.Int63n(size)
	data[start+randBytePos] ^= 1

	if err := Verify(&buf, bytes.NewReader(data), &tree, dataSize, start, size, root); err == nil {
		t.Errorf("Verification succeeded for modified data")
	}
}
