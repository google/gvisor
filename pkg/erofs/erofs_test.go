// Copyright 2023 The gVisor Authors.
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

package erofs

import (
	"testing"
)

func TestOnDiskStructureSizes(t *testing.T) {
	if sb := new(SuperBlock); sb.SizeBytes() != SuperBlockSize {
		t.Errorf("wrong superblock size: want %d, got %d", SuperBlockSize, sb.SizeBytes())
	}

	if i := new(InodeCompact); i.SizeBytes() != InodeCompactSize {
		t.Errorf("wrong compact inode size: want %d, got %d", InodeCompactSize, i.SizeBytes())
	}

	if i := new(InodeExtended); i.SizeBytes() != InodeExtendedSize {
		t.Errorf("wrong extended inode size: want %d, got %d", InodeExtendedSize, i.SizeBytes())
	}

	if d := new(Dirent); d.SizeBytes() != DirentSize {
		t.Errorf("wrong dirent size: want %d, got %d", DirentSize, d.SizeBytes())
	}
}
