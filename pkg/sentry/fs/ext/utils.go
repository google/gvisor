// Copyright 2019 The gVisor Authors.
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

package ext

import (
	"encoding/binary"
	"io"

	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/syserror"
)

// readFromDisk performs a binary read from disk into the given struct from
// the absolute offset provided.
//
// All disk reads should use this helper so we avoid reading from stale
// previously used offsets. This function forces the offset parameter.
func readFromDisk(dev io.ReadSeeker, abOff int64, v interface{}) error {
	if _, err := dev.Seek(abOff, io.SeekStart); err != nil {
		return syserror.EIO
	}

	if err := binary.Read(dev, binary.LittleEndian, v); err != nil {
		return syserror.EIO
	}

	return nil
}

// readSuperBlock reads the SuperBlock from block group 0 in the underlying
// device. There are three versions of the superblock. This function identifies
// and returns the correct version.
func readSuperBlock(dev io.ReadSeeker) (disklayout.SuperBlock, error) {
	var sb disklayout.SuperBlock = &disklayout.SuperBlockOld{}
	if err := readFromDisk(dev, disklayout.SbOffset, sb); err != nil {
		return nil, err
	}
	if sb.Revision() == disklayout.OldRev {
		return sb, nil
	}

	sb = &disklayout.SuperBlock32Bit{}
	if err := readFromDisk(dev, disklayout.SbOffset, sb); err != nil {
		return nil, err
	}
	if !sb.IncompatibleFeatures().Is64Bit {
		return sb, nil
	}

	sb = &disklayout.SuperBlock64Bit{}
	if err := readFromDisk(dev, disklayout.SbOffset, sb); err != nil {
		return nil, err
	}
	return sb, nil
}

// blockGroupsCount returns the number of block groups in the ext fs.
func blockGroupsCount(sb disklayout.SuperBlock) uint64 {
	blocksCount := sb.BlocksCount()
	blocksPerGroup := uint64(sb.BlocksPerGroup())

	// Round up the result. float64 can compromise precision so do it manually.
	bgCount := blocksCount / blocksPerGroup
	if blocksCount%blocksPerGroup != 0 {
		bgCount++
	}

	return bgCount
}

// readBlockGroups reads the block group descriptor table from block group 0 in
// the underlying device.
func readBlockGroups(dev io.ReadSeeker, sb disklayout.SuperBlock) ([]disklayout.BlockGroup, error) {
	bgCount := blockGroupsCount(sb)
	bgdSize := uint64(sb.BgDescSize())
	is64Bit := sb.IncompatibleFeatures().Is64Bit
	bgds := make([]disklayout.BlockGroup, bgCount)

	for i, off := uint64(0), uint64(sb.FirstDataBlock()+1)*sb.BlockSize(); i < bgCount; i, off = i+1, off+bgdSize {
		if is64Bit {
			bgds[i] = &disklayout.BlockGroup64Bit{}
		} else {
			bgds[i] = &disklayout.BlockGroup32Bit{}
		}

		if err := readFromDisk(dev, int64(off), bgds[i]); err != nil {
			return nil, err
		}
	}
	return bgds, nil
}
