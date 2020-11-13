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
	"errors"
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
		name                  string
		dataSize              int64
		hashAlgorithms        int
		dataAndTreeInSameFile bool
		expectedDigestSize    int64
		expectedLevelOffset   []int64
	}{
		{
			name:                  "SmallSizeSHA256SeparateFile",
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0},
		},
		{
			name:                  "SmallSizeSHA512SeparateFile",
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0},
		},
		{
			name:                  "SmallSizeSHA256SameFile",
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			name:                  "SmallSizeSHA512SameFile",
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{usermem.PageSize},
		},
		{
			name:                  "MiddleSizeSHA256SeparateFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 2 * usermem.PageSize, 3 * usermem.PageSize},
		},
		{
			name:                  "MiddleSizeSHA512SeparateFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 4 * usermem.PageSize, 5 * usermem.PageSize},
		},
		{
			name:                  "MiddleSizeSHA256SameFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 247 * usermem.PageSize, 248 * usermem.PageSize},
		},
		{
			name:                  "MiddleSizeSHA512SameFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{245 * usermem.PageSize, 249 * usermem.PageSize, 250 * usermem.PageSize},
		},
		{
			name:                  "LargeSizeSHA256SeparateFile",
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 32 * usermem.PageSize, 33 * usermem.PageSize},
		},
		{
			name:                  "LargeSizeSHA512SeparateFile",
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 64 * usermem.PageSize, 65 * usermem.PageSize},
		},
		{
			name:                  "LargeSizeSHA256SameFile",
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4128 * usermem.PageSize, 4129 * usermem.PageSize},
		},
		{
			name:                  "LargeSizeSHA512SameFile",
			dataSize:              4096 * int64(usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{4096 * usermem.PageSize, 4160 * usermem.PageSize, 4161 * usermem.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
		name                  string
		data                  []byte
		hashAlgorithms        int
		dataAndTreeInSameFile bool
		expectedHash          []byte
	}{
		{
			name:                  "OnePageZeroesSHA256SeparateFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{39, 30, 12, 152, 185, 58, 32, 84, 218, 79, 74, 113, 104, 219, 230, 234, 25, 126, 147, 36, 212, 44, 76, 74, 25, 93, 228, 41, 243, 143, 59, 147},
		},
		{
			name:                  "OnePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{39, 30, 12, 152, 185, 58, 32, 84, 218, 79, 74, 113, 104, 219, 230, 234, 25, 126, 147, 36, 212, 44, 76, 74, 25, 93, 228, 41, 243, 143, 59, 147},
		},
		{
			name:                  "OnePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{184, 76, 172, 204, 17, 136, 127, 75, 224, 42, 251, 181, 98, 149, 1, 44, 58, 148, 20, 187, 30, 174, 73, 87, 166, 9, 109, 169, 42, 96, 87, 202, 59, 82, 174, 80, 51, 95, 101, 100, 6, 246, 56, 120, 27, 166, 29, 59, 67, 115, 227, 121, 241, 177, 63, 238, 82, 157, 43, 107, 174, 180, 44, 84},
		},
		{
			name:                  "OnePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{184, 76, 172, 204, 17, 136, 127, 75, 224, 42, 251, 181, 98, 149, 1, 44, 58, 148, 20, 187, 30, 174, 73, 87, 166, 9, 109, 169, 42, 96, 87, 202, 59, 82, 174, 80, 51, 95, 101, 100, 6, 246, 56, 120, 27, 166, 29, 59, 67, 115, 227, 121, 241, 177, 63, 238, 82, 157, 43, 107, 174, 180, 44, 84},
		},
		{
			name:                  "MultiplePageZeroesSHA256SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{213, 221, 252, 9, 241, 250, 186, 1, 242, 132, 83, 77, 180, 207, 119, 48, 206, 113, 37, 253, 252, 159, 71, 70, 3, 53, 42, 244, 230, 244, 173, 143},
		},
		{
			name:                  "MultiplePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{213, 221, 252, 9, 241, 250, 186, 1, 242, 132, 83, 77, 180, 207, 119, 48, 206, 113, 37, 253, 252, 159, 71, 70, 3, 53, 42, 244, 230, 244, 173, 143},
		},
		{
			name:                  "MultiplePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{40, 231, 187, 28, 3, 171, 168, 36, 177, 244, 118, 131, 218, 226, 106, 55, 245, 157, 244, 147, 144, 57, 41, 182, 65, 6, 13, 49, 38, 66, 237, 117, 124, 110, 250, 246, 248, 132, 201, 156, 195, 201, 142, 179, 122, 128, 195, 194, 187, 240, 129, 171, 168, 182, 101, 58, 194, 155, 99, 147, 49, 130, 161, 178},
		},
		{
			name:                  "MultiplePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{40, 231, 187, 28, 3, 171, 168, 36, 177, 244, 118, 131, 218, 226, 106, 55, 245, 157, 244, 147, 144, 57, 41, 182, 65, 6, 13, 49, 38, 66, 237, 117, 124, 110, 250, 246, 248, 132, 201, 156, 195, 201, 142, 179, 122, 128, 195, 194, 187, 240, 129, 171, 168, 182, 101, 58, 194, 155, 99, 147, 49, 130, 161, 178},
		},
		{
			name:                  "SingleASHA256SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{182, 25, 170, 240, 16, 153, 234, 4, 101, 238, 197, 154, 182, 168, 171, 96, 177, 33, 171, 117, 73, 78, 124, 239, 82, 255, 215, 121, 156, 95, 121, 171},
		},
		{
			name:                  "SingleASHA256SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{182, 25, 170, 240, 16, 153, 234, 4, 101, 238, 197, 154, 182, 168, 171, 96, 177, 33, 171, 117, 73, 78, 124, 239, 82, 255, 215, 121, 156, 95, 121, 171},
		},
		{
			name:                  "SingleASHA512SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{121, 28, 140, 244, 32, 222, 61, 255, 184, 65, 117, 84, 132, 197, 122, 214, 95, 249, 164, 77, 211, 192, 217, 59, 109, 255, 249, 253, 27, 142, 110, 29, 93, 153, 92, 211, 178, 198, 136, 34, 61, 157, 141, 94, 145, 191, 201, 134, 141, 138, 51, 26, 33, 187, 17, 196, 113, 234, 125, 219, 4, 41, 57, 120},
		},
		{
			name:                  "SingleASHA512SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{121, 28, 140, 244, 32, 222, 61, 255, 184, 65, 117, 84, 132, 197, 122, 214, 95, 249, 164, 77, 211, 192, 217, 59, 109, 255, 249, 253, 27, 142, 110, 29, 93, 153, 92, 211, 178, 198, 136, 34, 61, 157, 141, 94, 145, 191, 201, 134, 141, 138, 51, 26, 33, 187, 17, 196, 113, 234, 125, 219, 4, 41, 57, 120},
		},
		{
			name:                  "OnePageASHA256SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{17, 40, 99, 150, 206, 124, 196, 184, 41, 40, 50, 91, 113, 47, 8, 204, 2, 102, 202, 86, 157, 92, 218, 53, 151, 250, 234, 247, 191, 121, 113, 246},
		},
		{
			name:                  "OnePageASHA256SameFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{17, 40, 99, 150, 206, 124, 196, 184, 41, 40, 50, 91, 113, 47, 8, 204, 2, 102, 202, 86, 157, 92, 218, 53, 151, 250, 234, 247, 191, 121, 113, 246},
		},
		{
			name:                  "OnePageASHA512SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{100, 22, 249, 78, 47, 163, 220, 231, 228, 165, 226, 192, 221, 77, 106, 69, 115, 104, 208, 155, 124, 206, 225, 233, 98, 249, 232, 225, 114, 119, 110, 216, 117, 106, 85, 7, 200, 206, 139, 81, 116, 37, 215, 158, 89, 110, 74, 86, 66, 95, 117, 237, 70, 56, 62, 175, 48, 147, 162, 122, 253, 57, 123, 84},
		},
		{
			name:                  "OnePageASHA512SameFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{100, 22, 249, 78, 47, 163, 220, 231, 228, 165, 226, 192, 221, 77, 106, 69, 115, 104, 208, 155, 124, 206, 225, 233, 98, 249, 232, 225, 114, 119, 110, 216, 117, 106, 85, 7, 200, 206, 139, 81, 116, 37, 215, 158, 89, 110, 74, 86, 66, 95, 117, 237, 70, 56, 62, 175, 48, 147, 162, 122, 253, 57, 123, 84},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf(tc.name), func(t *testing.T) {
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
				DataAndTreeInSameFile: tc.dataAndTreeInSameFile,
			}
			if tc.dataAndTreeInSameFile {
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
		})
	}
}

// prepareVerify generates test data and corresponding Merkle tree, and returns
// the prepared VerifyParams.
// The test data has size dataSize. The data is hashed with hashAlgorithms. The
// portion to be verified ranges from verifyStart with verifySize.
func prepareVerify(t *testing.T, dataSize int64, hashAlgorithm int, dataAndTreeInSameFile bool, verifyStart int64, verifySize int64, out io.Writer) ([]byte, VerifyParams) {
	t.Helper()
	data := make([]byte, dataSize)
	// Generate random bytes in data.
	rand.Read(data)

	var tree bytesReadWriter
	genParams := GenerateParams{
		Size:                  int64(len(data)),
		Name:                  defaultName,
		Mode:                  defaultMode,
		UID:                   defaultUID,
		GID:                   defaultGID,
		HashAlgorithms:        hashAlgorithm,
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
		t.Fatalf("could not generate Merkle tree:%v", err)
	}

	return data, VerifyParams{
		Out:                   out,
		File:                  bytes.NewReader(data),
		Tree:                  &tree,
		Size:                  dataSize,
		Name:                  defaultName,
		Mode:                  defaultMode,
		UID:                   defaultUID,
		GID:                   defaultGID,
		HashAlgorithms:        hashAlgorithm,
		ReadOffset:            verifyStart,
		ReadSize:              verifySize,
		Expected:              hash,
		DataAndTreeInSameFile: dataAndTreeInSameFile,
	}
}

func TestVerifyInvalidRange(t *testing.T) {
	testCases := []struct {
		name        string
		verifyStart int64
		verifySize  int64
	}{
		// Verify range starts outside data range.
		{
			name:        "StartOutsideRange",
			verifyStart: usermem.PageSize,
			verifySize:  1,
		},
		// Verify range ends outside data range.
		{
			name:        "EndOutsideRange",
			verifyStart: 0,
			verifySize:  2 * usermem.PageSize,
		},
		// Verify range with negative size.
		{
			name:        "NegativeSize",
			verifyStart: 1,
			verifySize:  -1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, linux.FS_VERITY_HASH_ALG_SHA256, false /* dataAndTreeInSameFile */, tc.verifyStart, tc.verifySize, &buf)
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyUnmodifiedMetadata(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, tc.hashAlgorithm, tc.dataAndTreeInSameFile, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			if _, err := Verify(&params); !errors.Is(err, nil) {
				t.Errorf("Verification failed when expected to succeed: %v", err)
			}
		})
	}
}

func TestVerifyModifiedName(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, tc.hashAlgorithm, tc.dataAndTreeInSameFile, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.Name += "abc"
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedSize(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, tc.hashAlgorithm, tc.dataAndTreeInSameFile, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.Size--
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedMode(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, tc.hashAlgorithm, tc.dataAndTreeInSameFile, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.Mode++
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedUID(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, tc.hashAlgorithm, tc.dataAndTreeInSameFile, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.UID++
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedGID(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, tc.hashAlgorithm, tc.dataAndTreeInSameFile, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.GID++
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestModifyOutsideVerifyRange(t *testing.T) {
	testCases := []struct {
		name string
		// The byte with index modifyByte is modified.
		modifyByte            int64
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "BeforeRangeSHA256SeparateFile",
			modifyByte:            4*usermem.PageSize - 1,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BeforeRangeSHA512SeparateFile",
			modifyByte:            4*usermem.PageSize - 1,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BeforeRangeSHA256SameFile",
			modifyByte:            4*usermem.PageSize - 1,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "BeforeRangeSHA512SameFile",
			modifyByte:            4*usermem.PageSize - 1,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "AfterRangeSHA256SeparateFile",
			modifyByte:            5 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "AfterRangeSHA512SeparateFile",
			modifyByte:            5 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "AfterRangeSHA256SameFile",
			modifyByte:            5 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "AfterRangeSHA256SameFile",
			modifyByte:            5 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(8 * usermem.PageSize)
			verifyStart := int64(4 * usermem.PageSize)
			verifySize := int64(usermem.PageSize)
			var buf bytes.Buffer
			// Modified byte is outside verify range. Verify should succeed.
			data, params := prepareVerify(t, dataSize, tc.hashAlgorithm, tc.dataAndTreeInSameFile, verifyStart, verifySize, &buf)
			// Flip a bit in data and checks Verify results.
			data[tc.modifyByte] ^= 1
			n, err := Verify(&params)
			if !errors.Is(err, nil) {
				t.Errorf("Verification failed when expected to succeed: %v", err)
			}
			if n != verifySize {
				t.Errorf("Got Verify output size %d, want %d", n, verifySize)
			}
			if int64(buf.Len()) != verifySize {
				t.Errorf("Got Verify output buf size %d, want %d,", buf.Len(), verifySize)
			}
			if !bytes.Equal(data[verifyStart:verifyStart+verifySize], buf.Bytes()) {
				t.Errorf("Incorrect output buf from Verify")
			}
		})
	}
}

func TestModifyInsideVerifyRange(t *testing.T) {
	testCases := []struct {
		name        string
		verifyStart int64
		verifySize  int64
		// The byte with index modifyByte is modified.
		modifyByte            int64
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		// Test a block-aligned verify range.
		// Modifying a byte in the verified range should cause verify
		// to fail.
		{
			name:                  "BlockAlignedRangeSHA256SeparateFile",
			verifyStart:           4 * usermem.PageSize,
			verifySize:            usermem.PageSize,
			modifyByte:            4 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BlockAlignedRangeSHA512SeparateFile",
			verifyStart:           4 * usermem.PageSize,
			verifySize:            usermem.PageSize,
			modifyByte:            4 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BlockAlignedRangeSHA256SameFile",
			verifyStart:           4 * usermem.PageSize,
			verifySize:            usermem.PageSize,
			modifyByte:            4 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "BlockAlignedRangeSHA512SameFile",
			verifyStart:           4 * usermem.PageSize,
			verifySize:            usermem.PageSize,
			modifyByte:            4 * usermem.PageSize,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
		// The tests below use a non-block-aligned verify range.
		// Modifying a byte at strat of verify range should cause
		// verify to fail.
		{
			name:                  "ModifyStartSHA256SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyStartSHA512SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyStartSHA256SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "ModifyStartSHA512SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte at the end of verify range should cause
		// verify to fail.
		{
			name:                  "ModifyEndSHA256SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyEndSHA512SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyEndSHA256SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "ModifyEndSHA512SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the middle verified block should cause
		// verify to fail.
		{
			name:                  "ModifyMiddleSHA256SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            5*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyMiddleSHA512SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            5*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyMiddleSHA256SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            5*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "ModifyMiddleSHA512SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            5*usermem.PageSize + 123,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the first block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			name:                  "ModifyFirstBlockSHA256SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 122,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyFirstBlockSHA512SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 122,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyFirstBlockSHA256SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 122,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "ModifyFirstBlockSHA512SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 122,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the last block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			name:                  "ModifyLastBlockSHA256SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 124,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyLastBlockSHA512SeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 124,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyLastBlockSHA256SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 124,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "ModifyLastBlockSHA512SameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 124,
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(8 * usermem.PageSize)
			var buf bytes.Buffer
			data, params := prepareVerify(t, dataSize, tc.hashAlgorithm, tc.dataAndTreeInSameFile, tc.verifyStart, tc.verifySize, &buf)
			// Flip a bit in data and checks Verify results.
			data[tc.modifyByte] ^= 1
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyRandom(t *testing.T) {
	testCases := []struct {
		name                  string
		hashAlgorithm         int
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SHA256SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA512SeparateFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SHA256SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "SHA512SameFile",
			hashAlgorithm:         linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rand.Seed(time.Now().UnixNano())
			// Use a random dataSize.  Minimum size 2 so that we can pick a random
			// portion from it.
			dataSize := rand.Int63n(200*usermem.PageSize) + 2

			// Pick a random portion of data.
			start := rand.Int63n(dataSize - 1)
			size := rand.Int63n(dataSize) + 1

			var buf bytes.Buffer
			data, params := prepareVerify(t, dataSize, tc.hashAlgorithm, tc.dataAndTreeInSameFile, start, size, &buf)

			// Checks that the random portion of data from the original data is
			// verified successfully.
			n, err := Verify(&params)
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
			params.Name = defaultName + "abc"
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Error("Verify succeeded for modified metadata, expect failure")
			}

			// Flip a random bit in randPortion, and check that verification fails.
			buf.Reset()
			randBytePos := rand.Int63n(size)
			data[start+randBytePos] ^= 1
			params.File = bytes.NewReader(data)
			params.Name = defaultName

			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Error("Verification succeeded for modified data, expect failure")
			}
		})
	}
}
