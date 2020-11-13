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
			expectedHash:          []byte{42, 197, 191, 52, 206, 122, 93, 34, 198, 125, 100, 154, 171, 177, 94, 14, 49, 40, 76, 157, 122, 58, 78, 6, 163, 248, 30, 238, 16, 190, 173, 175},
		},
		{
			name:                  "OnePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{42, 197, 191, 52, 206, 122, 93, 34, 198, 125, 100, 154, 171, 177, 94, 14, 49, 40, 76, 157, 122, 58, 78, 6, 163, 248, 30, 238, 16, 190, 173, 175},
		},
		{
			name:                  "OnePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{87, 131, 150, 74, 0, 218, 117, 114, 34, 23, 212, 16, 122, 97, 124, 172, 41, 46, 107, 150, 33, 46, 56, 39, 5, 246, 215, 187, 140, 83, 35, 63, 111, 74, 155, 241, 161, 214, 92, 141, 232, 125, 99, 71, 168, 102, 82, 20, 229, 249, 248, 28, 29, 238, 199, 223, 173, 180, 179, 46, 241, 240, 237, 74},
		},
		{
			name:                  "OnePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{87, 131, 150, 74, 0, 218, 117, 114, 34, 23, 212, 16, 122, 97, 124, 172, 41, 46, 107, 150, 33, 46, 56, 39, 5, 246, 215, 187, 140, 83, 35, 63, 111, 74, 155, 241, 161, 214, 92, 141, 232, 125, 99, 71, 168, 102, 82, 20, 229, 249, 248, 28, 29, 238, 199, 223, 173, 180, 179, 46, 241, 240, 237, 74},
		},
		{
			name:                  "MultiplePageZeroesSHA256SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{115, 151, 35, 147, 223, 91, 17, 6, 162, 145, 237, 81, 88, 53, 120, 49, 128, 70, 188, 28, 254, 241, 19, 233, 30, 243, 71, 225, 57, 58, 61, 38},
		},
		{
			name:                  "MultiplePageZeroesSHA256SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{115, 151, 35, 147, 223, 91, 17, 6, 162, 145, 237, 81, 88, 53, 120, 49, 128, 70, 188, 28, 254, 241, 19, 233, 30, 243, 71, 225, 57, 58, 61, 38},
		},
		{
			name:                  "MultiplePageZeroesSHA512SeparateFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{41, 94, 205, 97, 254, 226, 171, 69, 76, 102, 197, 47, 113, 53, 24, 244, 103, 131, 83, 73, 87, 212, 247, 140, 32, 144, 211, 158, 25, 131, 194, 57, 21, 224, 128, 119, 69, 100, 45, 50, 157, 54, 46, 214, 152, 179, 59, 78, 28, 48, 146, 160, 204, 48, 27, 90, 152, 193, 167, 45, 150, 67, 66, 217},
		},
		{
			name:                  "MultiplePageZeroesSHA512SameFile",
			data:                  bytes.Repeat([]byte{0}, 128*usermem.PageSize+1),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{41, 94, 205, 97, 254, 226, 171, 69, 76, 102, 197, 47, 113, 53, 24, 244, 103, 131, 83, 73, 87, 212, 247, 140, 32, 144, 211, 158, 25, 131, 194, 57, 21, 224, 128, 119, 69, 100, 45, 50, 157, 54, 46, 214, 152, 179, 59, 78, 28, 48, 146, 160, 204, 48, 27, 90, 152, 193, 167, 45, 150, 67, 66, 217},
		},
		{
			name:                  "SingleASHA256SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{52, 159, 140, 206, 140, 138, 231, 140, 94, 14, 252, 66, 175, 128, 191, 14, 52, 215, 190, 184, 165, 50, 182, 224, 42, 156, 145, 0, 1, 15, 187, 85},
		},
		{
			name:                  "SingleASHA256SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{52, 159, 140, 206, 140, 138, 231, 140, 94, 14, 252, 66, 175, 128, 191, 14, 52, 215, 190, 184, 165, 50, 182, 224, 42, 156, 145, 0, 1, 15, 187, 85},
		},
		{
			name:                  "SingleASHA512SeparateFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{232, 90, 223, 95, 60, 151, 149, 172, 174, 58, 206, 97, 189, 103, 6, 202, 67, 248, 1, 189, 243, 51, 250, 42, 5, 89, 195, 9, 50, 74, 39, 169, 114, 228, 109, 225, 128, 210, 63, 94, 18, 133, 58, 48, 225, 100, 176, 55, 87, 60, 235, 224, 143, 41, 15, 253, 94, 28, 251, 233, 99, 207, 152, 108},
		},
		{
			name:                  "SingleASHA512SameFile",
			data:                  []byte{'a'},
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{232, 90, 223, 95, 60, 151, 149, 172, 174, 58, 206, 97, 189, 103, 6, 202, 67, 248, 1, 189, 243, 51, 250, 42, 5, 89, 195, 9, 50, 74, 39, 169, 114, 228, 109, 225, 128, 210, 63, 94, 18, 133, 58, 48, 225, 100, 176, 55, 87, 60, 235, 224, 143, 41, 15, 253, 94, 28, 251, 233, 99, 207, 152, 108},
		},
		{
			name:                  "OnePageASHA256SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{157, 60, 139, 54, 248, 39, 187, 77, 31, 107, 241, 26, 240, 49, 83, 159, 182, 60, 128, 85, 121, 204, 15, 249, 44, 248, 127, 134, 58, 220, 41, 185},
		},
		{
			name:                  "OnePageASHA256SameFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA256,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{157, 60, 139, 54, 248, 39, 187, 77, 31, 107, 241, 26, 240, 49, 83, 159, 182, 60, 128, 85, 121, 204, 15, 249, 44, 248, 127, 134, 58, 220, 41, 185},
		},
		{
			name:                  "OnePageASHA512SeparateFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: false,
			expectedHash:          []byte{116, 22, 252, 100, 32, 241, 254, 228, 167, 228, 110, 146, 156, 189, 6, 30, 27, 127, 94, 181, 15, 98, 173, 60, 34, 102, 92, 174, 181, 80, 205, 90, 88, 12, 125, 194, 148, 175, 184, 168, 37, 66, 127, 194, 19, 132, 93, 147, 168, 217, 227, 131, 100, 25, 213, 255, 132, 60, 196, 217, 24, 158, 1, 50},
		},
		{
			name:                  "OnePageASHA512SameFile",
			data:                  bytes.Repeat([]byte{'a'}, usermem.PageSize),
			hashAlgorithms:        linux.FS_VERITY_HASH_ALG_SHA512,
			dataAndTreeInSameFile: true,
			expectedHash:          []byte{116, 22, 252, 100, 32, 241, 254, 228, 167, 228, 110, 146, 156, 189, 6, 30, 27, 127, 94, 181, 15, 98, 173, 60, 34, 102, 92, 174, 181, 80, 205, 90, 88, 12, 125, 194, 148, 175, 184, 168, 37, 66, 127, 194, 19, 132, 93, 147, 168, 217, 227, 131, 100, 25, 213, 255, 132, 60, 196, 217, 24, 158, 1, 50},
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

func TestVerifyModifiedChildren(t *testing.T) {
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
			params.Children["abc"] = struct{}{}
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
