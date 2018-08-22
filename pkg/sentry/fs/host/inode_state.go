// Copyright 2018 Google Inc.
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

package host

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// beforeSave is invoked by stateify.
func (i *inodeFileState) beforeSave() {
	if !i.queue.IsEmpty() {
		panic("event queue must be empty")
	}
	if !i.descriptor.donated && i.sattr.Type == fs.RegularFile {
		uattr, err := i.unstableAttr(context.Background())
		if err != nil {
			panic(fs.ErrSaveRejection{fmt.Errorf("failed to get unstable atttribute of %s: %v", i.mops.inodeMappings[i.sattr.InodeID], err)})
		}
		i.savedUAttr = &uattr
	}
}

// afterLoad is invoked by stateify.
func (i *inodeFileState) afterLoad() {
	// Initialize the descriptor value.
	if err := i.descriptor.initAfterLoad(i.mops, i.sattr.InodeID, &i.queue); err != nil {
		panic(fmt.Sprintf("failed to load value of descriptor: %v", err))
	}

	// Remap the inode number.
	var s syscall.Stat_t
	if err := syscall.Fstat(i.FD(), &s); err != nil {
		panic(fs.ErrCorruption{fmt.Errorf("failed to get metadata for fd %d: %v", i.FD(), err)})
	}
	key := device.MultiDeviceKey{
		Device: s.Dev,
		Inode:  s.Ino,
	}
	if !hostFileDevice.Load(key, i.sattr.InodeID) {
		// This means there was a conflict at s.Dev and s.Ino with
		// another inode mapping: two files that were unique on the
		// saved filesystem are no longer unique on this filesystem.
		// Since this violates the contract that filesystems cannot
		// change across save and restore, error out.
		panic(fs.ErrCorruption{fmt.Errorf("host %s conflict in host device mappings: %s", key, hostFileDevice)})
	}

	if !i.descriptor.donated && i.sattr.Type == fs.RegularFile {
		env, ok := fs.CurrentRestoreEnvironment()
		if !ok {
			panic("missing restore environment")
		}
		uattr := unstableAttr(i.mops, &s)
		if env.ValidateFileSize && uattr.Size != i.savedUAttr.Size {
			panic(fs.ErrCorruption{fmt.Errorf("file size has changed for %s: previously %d, now %d", i.mops.inodeMappings[i.sattr.InodeID], i.savedUAttr.Size, uattr.Size)})
		}
		if env.ValidateFileTimestamp && uattr.ModificationTime != i.savedUAttr.ModificationTime {
			panic(fs.ErrCorruption{fmt.Errorf("file modification time has changed for %s: previously %v, now %v", i.mops.inodeMappings[i.sattr.InodeID], i.savedUAttr.ModificationTime, uattr.ModificationTime)})
		}
		i.savedUAttr = nil
	}
}
