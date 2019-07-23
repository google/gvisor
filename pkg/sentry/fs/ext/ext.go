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

// Package ext implements readonly ext(2/3/4) filesystems.
package ext

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/syserror"
)

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	// dev is the ReadSeeker for the underlying fs device and is protected by mu.
	dev io.ReadSeeker

	// mu synchronizes the usage of dev. The ext filesystems take locality into
	// condsideration, i.e. data blocks of a file will tend to be placed close
	// together. On a spinning disk, locality reduces the amount of movement of
	// the head hence speeding up IO operations. On an SSD there are no moving
	// parts but locality increases the size of each transer request. Hence,
	// having mutual exclusion on the read seeker while reading a file *should*
	// help in achieving the intended performance gains.
	//
	// Note: This synchronization was not coupled with the ReadSeeker itself
	// because we want to synchronize across read/seek operations for the
	// performance gains mentioned above. Helps enforcing one-file-at-a-time IO.
	mu sync.Mutex

	// sb represents the filesystem superblock. Immutable after initialization.
	sb disklayout.SuperBlock

	// bgs represents all the block group descriptors for the filesystem.
	// Immutable after initialization.
	bgs []disklayout.BlockGroup
}

// newFilesystem is the filesystem constructor.
func newFilesystem(dev io.ReadSeeker) (*filesystem, error) {
	fs := filesystem{dev: dev}
	var err error

	fs.sb, err = readSuperBlock(dev)
	if err != nil {
		return nil, err
	}

	if fs.sb.Magic() != linux.EXT_SUPER_MAGIC {
		// mount(2) specifies that EINVAL should be returned if the superblock is
		// invalid.
		return nil, syserror.EINVAL
	}

	fs.bgs, err = readBlockGroups(dev, fs.sb)
	if err != nil {
		return nil, err
	}

	return &fs, nil
}
