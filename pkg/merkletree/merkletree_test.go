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
	defaultName          = "merkle_test"
	defaultMode          = 0644
	defaultUID           = 0
	defaultGID           = 0
	defaultSymlinkPath   = "merkle_test_link"
	defaultHashAlgorithm = linux.FS_VERITY_HASH_ALG_SHA256
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
			expectedHash:          []byte{9, 115, 238, 230, 38, 140, 195, 70, 207, 144, 202, 118, 23, 113, 32, 129, 226, 239, 177, 69, 161, 26, 14, 113, 16, 37, 30, 96, 19, 148, 132, 27},
		},
		{
			name:                  "OnePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{9, 115, 238, 230, 38, 140, 195, 70, 207, 144, 202, 118, 23, 113, 32, 129, 226, 239, 177, 69, 161, 26, 14, 113, 16, 37, 30, 96, 19, 148, 132, 27},
		},
		{
			name:                  "OnePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{127, 8, 95, 11, 83, 101, 51, 39, 170, 235, 39, 43, 135, 243, 145, 118, 148, 58, 27, 155, 182, 205, 44, 47, 5, 223, 215, 17, 35, 16, 43, 104, 43, 11, 8, 88, 171, 7, 249, 243, 14, 62, 126, 218, 23, 159, 237, 237, 42, 226, 39, 25, 87, 48, 253, 191, 116, 213, 37, 3, 187, 152, 154, 14},
		},
		{
			name:                  "OnePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{127, 8, 95, 11, 83, 101, 51, 39, 170, 235, 39, 43, 135, 243, 145, 118, 148, 58, 27, 155, 182, 205, 44, 47, 5, 223, 215, 17, 35, 16, 43, 104, 43, 11, 8, 88, 171, 7, 249, 243, 14, 62, 126, 218, 23, 159, 237, 237, 42, 226, 39, 25, 87, 48, 253, 191, 116, 213, 37, 3, 187, 152, 154, 14},
		},
		{
			name:                  "MultiplePageZeroesSHA256SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{247, 158, 42, 215, 180, 106, 0, 28, 77, 64, 132, 162, 74, 65, 250, 161, 243, 66, 129, 44, 197, 8, 145, 14, 94, 206, 156, 184, 145, 145, 20, 185},
		},
		{
			name:                  "MultiplePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{247, 158, 42, 215, 180, 106, 0, 28, 77, 64, 132, 162, 74, 65, 250, 161, 243, 66, 129, 44, 197, 8, 145, 14, 94, 206, 156, 184, 145, 145, 20, 185},
		},
		{
			name:                  "MultiplePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{100, 121, 14, 30, 104, 200, 142, 182, 190, 78, 23, 68, 157, 174, 23, 75, 174, 250, 250, 25, 66, 45, 235, 103, 129, 49, 78, 127, 173, 154, 121, 35, 37, 115, 60, 217, 26, 205, 253, 253, 236, 145, 107, 109, 232, 19, 72, 92, 4, 191, 181, 205, 191, 57, 234, 177, 144, 235, 143, 30, 15, 197, 109, 81},
		},
		{
			name:                  "MultiplePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{100, 121, 14, 30, 104, 200, 142, 182, 190, 78, 23, 68, 157, 174, 23, 75, 174, 250, 250, 25, 66, 45, 235, 103, 129, 49, 78, 127, 173, 154, 121, 35, 37, 115, 60, 217, 26, 205, 253, 253, 236, 145, 107, 109, 232, 19, 72, 92, 4, 191, 181, 205, 191, 57, 234, 177, 144, 235, 143, 30, 15, 197, 109, 81},
		},
		{
			name:                  "SingleASHA256SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{90, 124, 194, 100, 206, 242, 75, 152, 47, 249, 16, 27, 136, 161, 223, 228, 121, 241, 126, 158, 126, 122, 100, 120, 117, 15, 81, 78, 201, 133, 119, 111},
		},
		{
			name:                  "SingleASHA256SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{90, 124, 194, 100, 206, 242, 75, 152, 47, 249, 16, 27, 136, 161, 223, 228, 121, 241, 126, 158, 126, 122, 100, 120, 117, 15, 81, 78, 201, 133, 119, 111},
		},
		{
			name:                  "SingleASHA512SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{24, 10, 13, 25, 113, 62, 169, 99, 151, 70, 166, 113, 81, 81, 163, 85, 5, 25, 29, 15, 46, 37, 104, 120, 142, 218, 52, 178, 187, 83, 30, 166, 101, 87, 70, 196, 188, 61, 123, 20, 13, 254, 126, 52, 212, 111, 75, 203, 33, 233, 233, 47, 181, 161, 43, 193, 131, 41, 99, 33, 164, 73, 89, 152},
		},
		{
			name:                  "SingleASHA512SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{24, 10, 13, 25, 113, 62, 169, 99, 151, 70, 166, 113, 81, 81, 163, 85, 5, 25, 29, 15, 46, 37, 104, 120, 142, 218, 52, 178, 187, 83, 30, 166, 101, 87, 70, 196, 188, 61, 123, 20, 13, 254, 126, 52, 212, 111, 75, 203, 33, 233, 233, 47, 181, 161, 43, 193, 131, 41, 99, 33, 164, 73, 89, 152},
		},
		{
			name:                  "OnePageASHA256SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{132, 54, 112, 142, 156, 19, 50, 140, 138, 240, 192, 154, 100, 120, 242, 69, 64, 217, 62, 166, 127, 88, 23, 197, 100, 66, 255, 215, 214, 229, 54, 1},
		},
		{
			name:                  "OnePageASHA256SameFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{132, 54, 112, 142, 156, 19, 50, 140, 138, 240, 192, 154, 100, 120, 242, 69, 64, 217, 62, 166, 127, 88, 23, 197, 100, 66, 255, 215, 214, 229, 54, 1},
		},
		{
			name:                  "OnePageASHA512SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{165, 46, 176, 116, 47, 209, 101, 193, 64, 185, 30, 9, 52, 22, 24, 154, 135, 220, 232, 168, 215, 45, 222, 226, 207, 104, 160, 10, 156, 98, 245, 250, 76, 21, 68, 204, 65, 118, 69, 52, 210, 155, 36, 109, 233, 103, 1, 40, 218, 89, 125, 38, 247, 194, 2, 225, 119, 155, 65, 99, 182, 111, 110, 145},
		},
		{
			name:                  "OnePageASHA512SameFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{165, 46, 176, 116, 47, 209, 101, 193, 64, 185, 30, 9, 52, 22, 24, 154, 135, 220, 232, 168, 215, 45, 222, 226, 207, 104, 160, 10, 156, 98, 245, 250, 76, 21, 68, 204, 65, 118, 69, 52, 210, 155, 36, 109, 233, 103, 1, 40, 218, 89, 125, 38, 247, 194, 2, 225, 119, 155, 65, 99, 182, 111, 110, 145},
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
				Children:              make(map[string]struct{}),
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
// The test data has size dataSize. The data is hashed with hashAlgorithm. The
// portion to be verified is the range [verifyStart, verifyStart + verifySize).
func prepareVerify(t *testing.T, dataSize int64, hashAlgorithm int, dataAndTreeInSameFile, isSymlink bool, verifyStart, verifySize int64, out io.Writer) ([]byte, VerifyParams) {
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
		Children:              make(map[string]struct{}),
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

	if isSymlink {
		genParams.SymlinkTarget = defaultSymlinkPath
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
		Children:              make(map[string]struct{}),
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
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, false /* dataAndTreeInSameFile */, false /* isSymlink */, tc.verifyStart, tc.verifySize, &buf)
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyUnmodifiedMetadata(t *testing.T) {
	testCases := []struct {
		name                  string
		dataAndTreeInSameFile bool
		isSymlink             bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
			isSymlink:             true,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
			isSymlink:             false,
		},
		{
			name:                  "SameFileSymlink",
			dataAndTreeInSameFile: true,
			isSymlink:             true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, tc.isSymlink, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			if tc.isSymlink {
				params.SymlinkTarget = defaultSymlinkPath
			}
			if _, err := Verify(&params); !errors.Is(err, nil) {
				t.Errorf("Verification failed when expected to succeed: %v", err)
			}
		})
	}
}

func TestVerifyModifiedName(t *testing.T) {
	testCases := []struct {
		name                  string
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.GID++
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedChildren(t *testing.T) {
	testCases := []struct {
		name                  string
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "SeparateFile",
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "SameFile",
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.Children["abc"] = struct{}{}
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedSymlink(t *testing.T) {
	var buf bytes.Buffer
	_, params := prepareVerify(t, usermem.PageSize /* dataSize */, defaultHashAlgorithm, false /* dataAndTreeInSameFile */, true /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
	params.SymlinkTarget = "merkle_modified_test_link"
	if _, err := Verify(&params); err == nil {
		t.Errorf("Verification succeeded when expected to fail")
	}
}

func TestModifyOutsideVerifyRange(t *testing.T) {
	testCases := []struct {
		name string
		// The byte with index modifyByte is modified.
		modifyByte            int64
		dataAndTreeInSameFile bool
	}{
		{
			name:                  "BeforeRangeSeparateFile",
			modifyByte:            4*usermem.PageSize - 1,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BeforeRangeSameFile",
			modifyByte:            4*usermem.PageSize - 1,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "AfterRangeSeparateFile",
			modifyByte:            5 * usermem.PageSize,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "AfterRangeSameFile",
			modifyByte:            5 * usermem.PageSize,
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
			data, params := prepareVerify(t, dataSize, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, verifyStart, verifySize, &buf)
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
		dataAndTreeInSameFile bool
	}{
		// Test a block-aligned verify range.
		// Modifying a byte in the verified range should cause verify
		// to fail.
		{
			name:                  "BlockAlignedRangeSeparateFile",
			verifyStart:           4 * usermem.PageSize,
			verifySize:            usermem.PageSize,
			modifyByte:            4 * usermem.PageSize,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BlockAlignedRangeSameFile",
			verifyStart:           4 * usermem.PageSize,
			verifySize:            usermem.PageSize,
			modifyByte:            4 * usermem.PageSize,
			dataAndTreeInSameFile: true,
		},
		// The tests below use a non-block-aligned verify range.
		// Modifying a byte at strat of verify range should cause
		// verify to fail.
		{
			name:                  "ModifyStartSeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 123,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyStartSameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 123,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte at the end of verify range should cause
		// verify to fail.
		{
			name:                  "ModifyEndSeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 123,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyEndSameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 123,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the middle verified block should cause
		// verify to fail.
		{
			name:                  "ModifyMiddleSeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            5*usermem.PageSize + 123,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyMiddleSameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            5*usermem.PageSize + 123,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the first block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			name:                  "ModifyFirstBlockSeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 122,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyFirstBlockSameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            4*usermem.PageSize + 122,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the last block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			name:                  "ModifyLastBlockSeparateFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 124,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyLastBlockSameFile",
			verifyStart:           4*usermem.PageSize + 123,
			verifySize:            2 * usermem.PageSize,
			modifyByte:            6*usermem.PageSize + 124,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(8 * usermem.PageSize)
			var buf bytes.Buffer
			data, params := prepareVerify(t, dataSize, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, tc.verifyStart, tc.verifySize, &buf)
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
			data, params := prepareVerify(t, dataSize, tc.hashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, start, size, &buf)

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
