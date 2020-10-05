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
		dataSize              int64
		dataAndTreeInSameFile bool
		expectedLevelOffset   []int64
	}{
		{
			dataSize:              100,
			dataAndTreeInSameFile: false,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			dataAndTreeInSameFile: true,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              1000000,
			dataAndTreeInSameFile: false,
			expectedLevelOffset:   []int64{0, 2 * usermem.PageSize, 3 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			dataAndTreeInSameFile: true,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 247 * usermem.PageSize, 248 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			dataAndTreeInSameFile: false,
			expectedLevelOffset:   []int64{0, 32 * usermem.PageSize, 33 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			dataAndTreeInSameFile: true,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4128 * usermem.PageSize, 4129 * usermem.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			l := InitLayout(tc.dataSize, tc.dataAndTreeInSameFile)
			if l.blockSize != int64(usermem.PageSize) {
				t.Errorf("Got blockSize %d, want %d", l.blockSize, usermem.PageSize)
			}
			if l.digestSize != sha256DigestSize {
				t.Errorf("Got digestSize %d, want %d", l.digestSize, sha256DigestSize)
			}
			if l.numLevels() != len(tc.expectedLevelOffset) {
				t.Errorf("Got levels %d, want %d", l.numLevels(), len(tc.expectedLevelOffset))
			}
			for i := 0; i < l.numLevels() && i < len(tc.expectedLevelOffset); i++ {
				if l.levelOffset[i] != tc.expectedLevelOffset[i] {
					t.Errorf("Got levelStart[%d] %d, want %d", i, l.levelOffset[i], tc.expectedLevelOffset[i])
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
			for _, dataAndTreeInSameFile := range []bool{false, true} {
				var tree bytesReadWriter
				var root []byte
				var err error
				if dataAndTreeInSameFile {
					tree.Write(tc.data)
					root, err = Generate(&tree, int64(len(tc.data)), &tree, &tree, dataAndTreeInSameFile)
				} else {
					root, err = Generate(&bytesReadWriter{
						bytes: tc.data,
					}, int64(len(tc.data)), &tree, &tree, dataAndTreeInSameFile)
				}
				if err != nil {
					t.Fatalf("Got err: %v, want nil", err)
				}

				if !bytes.Equal(root, tc.expectedRoot) {
					t.Errorf("Got root: %v, want %v", root, tc.expectedRoot)
				}
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

			for _, dataAndTreeInSameFile := range []bool{false, true} {
				var tree bytesReadWriter
				var root []byte
				var err error
				if dataAndTreeInSameFile {
					tree.Write(data)
					root, err = Generate(&tree, int64(len(data)), &tree, &tree, dataAndTreeInSameFile)
				} else {
					root, err = Generate(&bytesReadWriter{
						bytes: data,
					}, int64(tc.dataSize), &tree, &tree, false /* dataAndTreeInSameFile */)
				}
				if err != nil {
					t.Fatalf("Generate failed: %v", err)
				}

				// Flip a bit in data and checks Verify results.
				var buf bytes.Buffer
				data[tc.modifyByte] ^= 1
				if tc.shouldSucceed {
					n, err := Verify(&buf, bytes.NewReader(data), &tree, tc.dataSize, tc.verifyStart, tc.verifySize, root, dataAndTreeInSameFile)
					if err != nil && err != io.EOF {
						t.Errorf("Verification failed when expected to succeed: %v", err)
					}
					if n != tc.verifySize {
						t.Errorf("Got Verify output size %d, want %d", n, tc.verifySize)
					}
					if int64(buf.Len()) != tc.verifySize {
						t.Errorf("Got Verify output buf size %d, want %d,", buf.Len(), tc.verifySize)
					}
					if !bytes.Equal(data[tc.verifyStart:tc.verifyStart+tc.verifySize], buf.Bytes()) {
						t.Errorf("Incorrect output buf from Verify")
					}
				} else {
					if _, err := Verify(&buf, bytes.NewReader(data), &tree, tc.dataSize, tc.verifyStart, tc.verifySize, root, dataAndTreeInSameFile); err == nil {
						t.Errorf("Verification succeeded when expected to fail")
					}
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

	for _, dataAndTreeInSameFile := range []bool{false, true} {
		var tree bytesReadWriter
		var root []byte
		var err error
		if dataAndTreeInSameFile {
			tree.Write(data)
			root, err = Generate(&tree, int64(len(data)), &tree, &tree, dataAndTreeInSameFile)
		} else {
			root, err = Generate(&bytesReadWriter{
				bytes: data,
			}, int64(dataSize), &tree, &tree, dataAndTreeInSameFile)
		}
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}

		// Pick a random portion of data.
		start := rand.Int63n(dataSize - 1)
		size := rand.Int63n(dataSize) + 1

		var buf bytes.Buffer
		// Checks that the random portion of data from the original data is
		// verified successfully.
		n, err := Verify(&buf, bytes.NewReader(data), &tree, dataSize, start, size, root, dataAndTreeInSameFile)
		if err != nil && err != io.EOF {
			t.Errorf("Verification failed for correct data: %v", err)
		}
		if size > dataSize-start {
			size = dataSize - start
		}
		if n != size {
			t.Errorf("Got Verify output size %d, want %d", n, size)
		}
		if int64(buf.Len()) != size {
			t.Errorf("Got Verify output buf size %d, want %d", buf.Len(), size)
		}
		if !bytes.Equal(data[start:start+size], buf.Bytes()) {
			t.Errorf("Incorrect output buf from Verify")
		}

		buf.Reset()
		// Flip a random bit in randPortion, and check that verification fails.
		randBytePos := rand.Int63n(size)
		data[start+randBytePos] ^= 1

		if _, err := Verify(&buf, bytes.NewReader(data), &tree, dataSize, start, size, root, dataAndTreeInSameFile); err == nil {
			t.Errorf("Verification succeeded for modified data")
		}
	}
}
