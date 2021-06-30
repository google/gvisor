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

	"gvisor.dev/gvisor/pkg/hostarch"
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
			expectedLevelOffset:   []int64{hostarch.PageSize},
		},
		{
			name:                  "SmallSizeSHA512SameFile",
			dataSize:              100,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{hostarch.PageSize},
		},
		{
			name:                  "MiddleSizeSHA256SeparateFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 2 * hostarch.PageSize, 3 * hostarch.PageSize},
		},
		{
			name:                  "MiddleSizeSHA512SeparateFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 4 * hostarch.PageSize, 5 * hostarch.PageSize},
		},
		{
			name:                  "MiddleSizeSHA256SameFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{245 * hostarch.PageSize, 247 * hostarch.PageSize, 248 * hostarch.PageSize},
		},
		{
			name:                  "MiddleSizeSHA512SameFile",
			dataSize:              1000000,
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{245 * hostarch.PageSize, 249 * hostarch.PageSize, 250 * hostarch.PageSize},
		},
		{
			name:                  "LargeSizeSHA256SeparateFile",
			dataSize:              4096 * int64(hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{0, 32 * hostarch.PageSize, 33 * hostarch.PageSize},
		},
		{
			name:                  "LargeSizeSHA512SeparateFile",
			dataSize:              4096 * int64(hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{0, 64 * hostarch.PageSize, 65 * hostarch.PageSize},
		},
		{
			name:                  "LargeSizeSHA256SameFile",
			dataSize:              4096 * int64(hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    32,
			expectedLevelOffset:   []int64{4096 * hostarch.PageSize, 4128 * hostarch.PageSize, 4129 * hostarch.PageSize},
		},
		{
			name:                  "LargeSizeSHA512SameFile",
			dataSize:              4096 * int64(hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedDigestSize:    64,
			expectedLevelOffset:   []int64{4096 * hostarch.PageSize, 4160 * hostarch.PageSize, 4161 * hostarch.PageSize},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := InitLayout(tc.dataSize, tc.hashAlgorithms, tc.dataAndTreeInSameFile)
			if err != nil {
				t.Fatalf("Failed to InitLayout: %v", err)
			}
			if l.blockSize != int64(hostarch.PageSize) {
				t.Errorf("Got blockSize %d, want %d", l.blockSize, hostarch.PageSize)
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
			data:                  bytes.Repeat([]byte{0}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{78, 38, 225, 107, 61, 246, 26, 6, 71, 163, 254, 97, 112, 200, 87, 232, 190, 87, 231, 160, 119, 124, 61, 229, 49, 126, 90, 223, 134, 51, 77, 182},
		},
		{
			name:                  "OnePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{78, 38, 225, 107, 61, 246, 26, 6, 71, 163, 254, 97, 112, 200, 87, 232, 190, 87, 231, 160, 119, 124, 61, 229, 49, 126, 90, 223, 134, 51, 77, 182},
		},
		{
			name:                  "OnePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{221, 45, 182, 132, 61, 212, 227, 145, 150, 131, 98, 221, 195, 5, 89, 21, 188, 36, 250, 101, 85, 78, 197, 253, 193, 23, 74, 219, 28, 108, 77, 47, 65, 79, 123, 144, 50, 245, 109, 72, 71, 80, 24, 77, 158, 95, 242, 185, 109, 163, 105, 183, 67, 106, 55, 194, 223, 46, 12, 242, 165, 203, 172, 254},
		},
		{
			name:                  "OnePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{221, 45, 182, 132, 61, 212, 227, 145, 150, 131, 98, 221, 195, 5, 89, 21, 188, 36, 250, 101, 85, 78, 197, 253, 193, 23, 74, 219, 28, 108, 77, 47, 65, 79, 123, 144, 50, 245, 109, 72, 71, 80, 24, 77, 158, 95, 242, 185, 109, 163, 105, 183, 67, 106, 55, 194, 223, 46, 12, 242, 165, 203, 172, 254},
		},
		{
			name:                  "MultiplePageZeroesSHA256SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*hostarch.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{131, 122, 73, 143, 4, 202, 193, 156, 218, 169, 196, 223, 70, 100, 117, 191, 241, 113, 134, 11, 229, 231, 105, 157, 156, 0, 66, 213, 122, 145, 174, 8},
		},
		{
			name:                  "MultiplePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*hostarch.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{131, 122, 73, 143, 4, 202, 193, 156, 218, 169, 196, 223, 70, 100, 117, 191, 241, 113, 134, 11, 229, 231, 105, 157, 156, 0, 66, 213, 122, 145, 174, 8},
		},
		{
			name:                  "MultiplePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*hostarch.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{211, 48, 232, 110, 240, 51, 99, 241, 123, 138, 42, 76, 94, 86, 59, 200, 3, 246, 137, 148, 189, 226, 111, 103, 146, 29, 12, 218, 40, 182, 33, 99, 193, 163, 238, 26, 184, 13, 165, 187, 68, 173, 139, 9, 208, 59, 0, 192, 180, 50, 221, 35, 43, 119, 194, 16, 64, 84, 116, 63, 158, 195, 194, 226},
		},
		{
			name:                  "MultiplePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*hostarch.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{211, 48, 232, 110, 240, 51, 99, 241, 123, 138, 42, 76, 94, 86, 59, 200, 3, 246, 137, 148, 189, 226, 111, 103, 146, 29, 12, 218, 40, 182, 33, 99, 193, 163, 238, 26, 184, 13, 165, 187, 68, 173, 139, 9, 208, 59, 0, 192, 180, 50, 221, 35, 43, 119, 194, 16, 64, 84, 116, 63, 158, 195, 194, 226},
		},
		{
			name:                  "SingleASHA256SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{26, 47, 238, 138, 235, 244, 140, 231, 129, 240, 155, 252, 219, 44, 46, 72, 57, 249, 139, 88, 132, 238, 86, 108, 181, 115, 96, 72, 99, 210, 134, 47},
		},
		{
			name:                  "SingleASHA256SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{26, 47, 238, 138, 235, 244, 140, 231, 129, 240, 155, 252, 219, 44, 46, 72, 57, 249, 139, 88, 132, 238, 86, 108, 181, 115, 96, 72, 99, 210, 134, 47},
		},
		{
			name:                  "SingleASHA512SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{44, 30, 224, 12, 102, 119, 163, 171, 119, 175, 212, 121, 231, 188, 125, 171, 79, 28, 144, 234, 75, 122, 44, 75, 15, 101, 173, 92, 233, 109, 234, 60, 173, 148, 125, 85, 94, 234, 95, 91, 16, 196, 88, 175, 23, 129, 226, 110, 24, 238, 5, 49, 186, 128, 72, 188, 193, 180, 207, 193, 203, 119, 40, 191},
		},
		{
			name:                  "SingleASHA512SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{44, 30, 224, 12, 102, 119, 163, 171, 119, 175, 212, 121, 231, 188, 125, 171, 79, 28, 144, 234, 75, 122, 44, 75, 15, 101, 173, 92, 233, 109, 234, 60, 173, 148, 125, 85, 94, 234, 95, 91, 16, 196, 88, 175, 23, 129, 226, 110, 24, 238, 5, 49, 186, 128, 72, 188, 193, 180, 207, 193, 203, 119, 40, 191},
		},
		{
			name:                  "OnePageASHA256SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{166, 254, 83, 46, 241, 111, 18, 47, 79, 6, 181, 197, 176, 143, 211, 204, 53, 5, 245, 134, 172, 95, 97, 131, 236, 132, 197, 138, 123, 78, 43, 13},
		},
		{
			name:                  "OnePageASHA256SameFile",
			data:                  bytes.Repeat([]byte{'a'}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{166, 254, 83, 46, 241, 111, 18, 47, 79, 6, 181, 197, 176, 143, 211, 204, 53, 5, 245, 134, 172, 95, 97, 131, 236, 132, 197, 138, 123, 78, 43, 13},
		},
		{
			name:                  "OnePageASHA512SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{23, 69, 6, 79, 39, 232, 90, 246, 62, 55, 4, 229, 47, 36, 230, 24, 233, 47, 55, 36, 26, 139, 196, 78, 242, 12, 194, 77, 109, 81, 151, 188, 63, 201, 127, 235, 81, 214, 91, 200, 19, 232, 240, 14, 197, 1, 99, 224, 18, 213, 203, 242, 44, 102, 25, 62, 90, 189, 106, 107, 129, 61, 115, 39},
		},
		{
			name:                  "OnePageASHA512SameFile",
			data:                  bytes.Repeat([]byte{'a'}, hostarch.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{23, 69, 6, 79, 39, 232, 90, 246, 62, 55, 4, 229, 47, 36, 230, 24, 233, 47, 55, 36, 26, 139, 196, 78, 242, 12, 194, 77, 109, 81, 151, 188, 63, 201, 127, 235, 81, 214, 91, 200, 19, 232, 240, 14, 197, 1, 99, 224, 18, 213, 203, 242, 44, 102, 25, 62, 90, 189, 106, 107, 129, 61, 115, 39},
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
				Children:              []string{},
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
		Children:              []string{},
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
		Children:              []string{},
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
			verifyStart: hostarch.PageSize,
			verifySize:  1,
		},
		// Verify range ends outside data range.
		{
			name:        "EndOutsideRange",
			verifyStart: 0,
			verifySize:  2 * hostarch.PageSize,
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, false /* dataAndTreeInSameFile */, false /* isSymlink */, tc.verifyStart, tc.verifySize, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, tc.isSymlink, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, tc.dataAndTreeInSameFile, false /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
			params.Children = append(params.Children, "abc")
			if _, err := Verify(&params); errors.Is(err, nil) {
				t.Errorf("Verification succeeded when expected to fail")
			}
		})
	}
}

func TestVerifyModifiedSymlink(t *testing.T) {
	var buf bytes.Buffer
	_, params := prepareVerify(t, hostarch.PageSize /* dataSize */, defaultHashAlgorithm, false /* dataAndTreeInSameFile */, true /* isSymlink */, 0 /* verifyStart */, 0 /* verifySize */, &buf)
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
			modifyByte:            4*hostarch.PageSize - 1,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BeforeRangeSameFile",
			modifyByte:            4*hostarch.PageSize - 1,
			dataAndTreeInSameFile: true,
		},
		{
			name:                  "AfterRangeSeparateFile",
			modifyByte:            5 * hostarch.PageSize,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "AfterRangeSameFile",
			modifyByte:            5 * hostarch.PageSize,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(8 * hostarch.PageSize)
			verifyStart := int64(4 * hostarch.PageSize)
			verifySize := int64(hostarch.PageSize)
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
			verifyStart:           4 * hostarch.PageSize,
			verifySize:            hostarch.PageSize,
			modifyByte:            4 * hostarch.PageSize,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "BlockAlignedRangeSameFile",
			verifyStart:           4 * hostarch.PageSize,
			verifySize:            hostarch.PageSize,
			modifyByte:            4 * hostarch.PageSize,
			dataAndTreeInSameFile: true,
		},
		// The tests below use a non-block-aligned verify range.
		// Modifying a byte at strat of verify range should cause
		// verify to fail.
		{
			name:                  "ModifyStartSeparateFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            4*hostarch.PageSize + 123,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyStartSameFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            4*hostarch.PageSize + 123,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte at the end of verify range should cause
		// verify to fail.
		{
			name:                  "ModifyEndSeparateFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            6*hostarch.PageSize + 123,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyEndSameFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            6*hostarch.PageSize + 123,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the middle verified block should cause
		// verify to fail.
		{
			name:                  "ModifyMiddleSeparateFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            5*hostarch.PageSize + 123,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyMiddleSameFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            5*hostarch.PageSize + 123,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the first block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			name:                  "ModifyFirstBlockSeparateFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            4*hostarch.PageSize + 122,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyFirstBlockSameFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            4*hostarch.PageSize + 122,
			dataAndTreeInSameFile: true,
		},
		// Modifying a byte in the last block in the verified range
		// should cause verify to fail, even the modified bit itself is
		// out of verify range.
		{
			name:                  "ModifyLastBlockSeparateFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            6*hostarch.PageSize + 124,
			dataAndTreeInSameFile: false,
		},
		{
			name:                  "ModifyLastBlockSameFile",
			verifyStart:           4*hostarch.PageSize + 123,
			verifySize:            2 * hostarch.PageSize,
			modifyByte:            6*hostarch.PageSize + 124,
			dataAndTreeInSameFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataSize := int64(8 * hostarch.PageSize)
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
			dataSize := rand.Int63n(200*hostarch.PageSize) + 2

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
