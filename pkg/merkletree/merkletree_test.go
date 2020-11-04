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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/usermem"
)

func TestLayout(t *testing.T) {
	testCases := []struct {
		dataSize              int64
		hashAlgorithms        int
		dataAndTreeInSameFile bool
		expectedDigestSize    int64
		expectedLevelOffset   []int64
	}{
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 2 * usermem.PageSize, 3 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 4 * usermem.PageSize, 5 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 247 * usermem.PageSize, 248 * usermem.PageSize},
		},
		{
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 249 * usermem.PageSize, 250 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 32 * usermem.PageSize, 33 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 64 * usermem.PageSize, 65 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4128 * usermem.PageSize, 4129 * usermem.PageSize},
		},
		{
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4160 * usermem.PageSize, 4161 * usermem.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d", tc.dataSize), func(t *testing.T) {
			l, err := InitLayout(tc.dataSize, tc.hashAlgorithms, tc.dataAndTreeInSameFile)
			if err != nil {
				t.Fatalf("Failed to InitLayout: %v", err)
			}
			if l.blockSize != int64(usermem.PageSize) {
				t.Errorf("Got blockSize %d, want %d", l.blockSize, usermem.PageSize)
			}
			if l.digestSize != tc.expectedDigestSize {
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

const (
	defaultName = "merkle_test"
	defaultMode = 0644
	defaultUID  = 0
	defaultGID  = 0
)

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

func (brw *bytesReadWriter) ReadAt(p []byte, off int64) (int, error) {
	bytesRead := copy(p, brw.bytes[off:])
	if bytesRead == 0 {
		return bytesRead, io.EOF
	}
	return bytesRead, nil
}

func TestGenerate(t *testing.T) {
	// The input data has size dataSize. It starts with the data in startWith,
	// and all other bytes are zeroes.
	testCases := []struct {
		data           []byte
		hashAlgorithms int
		expectedHash   []byte
	}{
		{
			data:           bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{39, 30, 12, 152, 185, 58, 32, 84, 218, 79, 74, 113, 104, 219, 230, 234, 25, 126, 147, 36, 212, 44, 76, 74, 25, 93, 228, 41, 243, 143, 59, 147},
		},
		{
			data:           bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{184, 76, 172, 204, 17, 136, 127, 75, 224, 42, 251, 181, 98, 149, 1, 44, 58, 148, 20, 187, 30, 174, 73, 87, 166, 9, 109, 169, 42, 96, 87, 202, 59, 82, 174, 80, 51, 95, 101, 100, 6, 246, 56, 120, 27, 166, 29, 59, 67, 115, 227, 121, 241, 177, 63, 238, 82, 157, 43, 107, 174, 180, 44, 84},
		},
		{
			data:           bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{213, 221, 252, 9, 241, 250, 186, 1, 242, 132, 83, 77, 180, 207, 119, 48, 206, 113, 37, 253, 252, 159, 71, 70, 3, 53, 42, 244, 230, 244, 173, 143},
		},
		{
			data:           bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{40, 231, 187, 28, 3, 171, 168, 36, 177, 244, 118, 131, 218, 226, 106, 55, 245, 157, 244, 147, 144, 57, 41, 182, 65, 6, 13, 49, 38, 66, 237, 117, 124, 110, 250, 246, 248, 132, 201, 156, 195, 201, 142, 179, 122, 128, 195, 194, 187, 240, 129, 171, 168, 182, 101, 58, 194, 155, 99, 147, 49, 130, 161, 178},
		},
		{
			data:           []byte{'a'},
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{182, 25, 170, 240, 16, 153, 234, 4, 101, 238, 197, 154, 182, 168, 171, 96, 177, 33, 171, 117, 73, 78, 124, 239, 82, 255, 215, 121, 156, 95, 121, 171},
		},
		{
			data:           []byte{'a'},
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{121, 28, 140, 244, 32, 222, 61, 255, 184, 65, 117, 84, 132, 197, 122, 214, 95, 249, 164, 77, 211, 192, 217, 59, 109, 255, 249, 253, 27, 142, 110, 29, 93, 153, 92, 211, 178, 198, 136, 34, 61, 157, 141, 94, 145, 191, 201, 134, 141, 138, 51, 26, 33, 187, 17, 196, 113, 234, 125, 219, 4, 41, 57, 120},
		},
		{
			data:           bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA256,
			expectedHash:   []byte{17, 40, 99, 150, 206, 124, 196, 184, 41, 40, 50, 91, 113, 47, 8, 204, 2, 102, 202, 86, 157, 92, 218, 53, 151, 250, 234, 247, 191, 121, 113, 246},
		},
		{
			data:           bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms: linux.FS_VERITY_HASH_ALG_SHA512,
			expectedHash:   []byte{100, 22, 249, 78, 47, 163, 220, 231, 228, 165, 226, 192, 221, 77, 106, 69, 115, 104, 208, 155, 124, 206, 225, 233, 98, 249, 232, 225, 114, 119, 110, 216, 117, 106, 85, 7, 200, 206, 139, 81, 116, 37, 215, 158, 89, 110, 74, 86, 66, 95, 117, 237, 70, 56, 62, 175, 48, 147, 162, 122, 253, 57, 123, 84},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d:%v", len(tc.data), tc.data[0]), func(t *testing.T) {
			for _, dataAndTreeInSameFile := range []bool{false, true} {
				var tree bytesReadWriter
				params := GenerateParams{
					Size:                  int64(len(tc.data)),
					Name:                  defaultName,
					Mode:                  defaultMode,
					UID:                   defaultUID,
					GID:                   defaultGID,
					HashAlgorithms:        tc.hashAlgorithms,
					TreeReader:            &tree,
					TreeWriter:            &tree,
					DataAndTreeInSameFile: dataAndTreeInSameFile,
				}
				if dataAndTreeInSameFile {
					tree.Write(tc.data)
					params.File = &tree
				} else {
					params.File = &bytesReadWriter{
						bytes: tc.data,
					}
				}
				hash, err := Generate(&params)
				if err != nil {
					t.Fatalf("Got err: %v, want nil", err)
				}

				if !bytes.Equal(hash, tc.expectedHash) {
					t.Errorf("Got hash: %v, want %v", hash, tc.expectedHash)
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
		modifyName    bool
		modifySize    bool
		modifyMode    bool
		modifyUID     bool
		modifyGID     bool
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
		// 0 verify size should only verify metadata.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			shouldSucceed: true,
		},
		// Modified name should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyName:    true,
			shouldSucceed: false,
		},
		// Modified size should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifySize:    true,
			shouldSucceed: false,
		},
		// Modified mode should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyMode:    true,
			shouldSucceed: false,
		},
		// Modified UID should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyUID:     true,
			shouldSucceed: false,
		},
		// Modified GID should fail verification.
		{
			dataSize:      usermem.PageSize,
			verifyStart:   0,
			verifySize:    0,
			modifyByte:    0,
			modifyGID:     true,
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

			for _, hashAlgorithms := range []int{linux.FS_VERITY_HASH_ALG_SHA256, linux.FS_VERITY_HASH_ALG_SHA512} {
				for _, dataAndTreeInSameFile := range []bool{false, true} {
					var tree bytesReadWriter
					genParams := GenerateParams{
						Size:                  int64(len(data)),
						Name:                  defaultName,
						Mode:                  defaultMode,
						UID:                   defaultUID,
						GID:                   defaultGID,
						HashAlgorithms:        hashAlgorithms,
						TreeReader:            &tree,
						TreeWriter:            &tree,
						DataAndTreeInSameFile: dataAndTreeInSameFile,
					}
					if dataAndTreeInSameFile {
						tree.Write(data)
						genParams.File = &tree
					} else {
						genParams.File = &bytesReadWriter{
							bytes: data,
						}
					}
					hash, err := Generate(&genParams)
					if err != nil {
						t.Fatalf("Generate failed: %v", err)
					}

					// Flip a bit in data and checks Verify results.
					var buf bytes.Buffer
					data[tc.modifyByte] ^= 1
					verifyParams := VerifyParams{
						Out:                   &buf,
						File:                  bytes.NewReader(data),
						Tree:                  &tree,
						Size:                  tc.dataSize,
						Name:                  defaultName,
						Mode:                  defaultMode,
						UID:                   defaultUID,
						GID:                   defaultGID,
						HashAlgorithms:        hashAlgorithms,
						ReadOffset:            tc.verifyStart,
						ReadSize:              tc.verifySize,
						Expected:              hash,
						DataAndTreeInSameFile: dataAndTreeInSameFile,
					}
					if tc.modifyName {
						verifyParams.Name = defaultName + "abc"
					}
					if tc.modifySize {
						verifyParams.Size--
					}
					if tc.modifyMode {
						verifyParams.Mode = defaultMode + 1
					}
					if tc.modifyUID {
						verifyParams.UID = defaultUID + 1
					}
					if tc.modifyGID {
						verifyParams.GID = defaultGID + 1
					}
					if tc.shouldSucceed {
						n, err := Verify(&verifyParams)
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
						if _, err := Verify(&verifyParams); err == nil {
							t.Errorf("Verification succeeded when expected to fail")
						}
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

	for _, hashAlgorithms := range []int{linux.FS_VERITY_HASH_ALG_SHA256, linux.FS_VERITY_HASH_ALG_SHA512} {
		for _, dataAndTreeInSameFile := range []bool{false, true} {
			var tree bytesReadWriter
			genParams := GenerateParams{
				Size:                  int64(len(data)),
				Name:                  defaultName,
				Mode:                  defaultMode,
				UID:                   defaultUID,
				GID:                   defaultGID,
				HashAlgorithms:        hashAlgorithms,
				TreeReader:            &tree,
				TreeWriter:            &tree,
				DataAndTreeInSameFile: dataAndTreeInSameFile,
			}

			if dataAndTreeInSameFile {
				tree.Write(data)
				genParams.File = &tree
			} else {
				genParams.File = &bytesReadWriter{
					bytes: data,
				}
			}
			hash, err := Generate(&genParams)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			// Pick a random portion of data.
			start := rand.Int63n(dataSize - 1)
			size := rand.Int63n(dataSize) + 1

			var buf bytes.Buffer
			verifyParams := VerifyParams{
				Out:                   &buf,
				File:                  bytes.NewReader(data),
				Tree:                  &tree,
				Size:                  dataSize,
				Name:                  defaultName,
				Mode:                  defaultMode,
				UID:                   defaultUID,
				GID:                   defaultGID,
				HashAlgorithms:        hashAlgorithms,
				ReadOffset:            start,
				ReadSize:              size,
				Expected:              hash,
				DataAndTreeInSameFile: dataAndTreeInSameFile,
			}

			// Checks that the random portion of data from the original data is
			// verified successfully.
			n, err := Verify(&verifyParams)
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

			// Verify that modified metadata should fail verification.
			buf.Reset()
			verifyParams.Name = defaultName + "abc"
			if _, err := Verify(&verifyParams); err == nil {
				t.Error("Verify succeeded for modified metadata, expect failure")
			}

			// Flip a random bit in randPortion, and check that verification fails.
			buf.Reset()
			randBytePos := rand.Int63n(size)
			data[start+randBytePos] ^= 1
			verifyParams.File = bytes.NewReader(data)
			verifyParams.Name = defaultName

			if _, err := Verify(&verifyParams); err == nil {
				t.Error("Verification succeeded for modified data, expect failure")
			}
		}
	}
}
