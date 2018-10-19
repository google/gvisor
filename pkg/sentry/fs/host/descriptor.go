// Copyright 2018 Google LLC
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
	"path"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
	"gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier"
)

// descriptor wraps a host fd.
//
// +stateify savable
type descriptor struct {
	// donated is true if the host fd was donated by another process.
	donated bool

	// If origFD >= 0, it is the host fd that this file was originally created
	// from, which must be available at time of restore. The FD can be closed
	// after descriptor is created. Only set if donated is true.
	origFD int

	// wouldBlock is true if value (below) points to a file that can
	// return EWOULDBLOCK for operations that would block.
	wouldBlock bool

	// value is the wrapped host fd. It is never saved or restored
	// directly. How it is restored depends on whether it was
	// donated and the fs.MountSource it was originally
	// opened/created from.
	value int `state:"nosave"`
}

// newDescriptor returns a wrapped host file descriptor. On success,
// the descriptor is registered for event notifications with queue.
func newDescriptor(fd int, donated bool, saveable bool, wouldBlock bool, queue *waiter.Queue) (*descriptor, error) {
	ownedFD := fd
	origFD := -1
	if saveable {
		var err error
		ownedFD, err = syscall.Dup(fd)
		if err != nil {
			return nil, err
		}
		origFD = fd
	}
	if wouldBlock {
		if err := syscall.SetNonblock(ownedFD, true); err != nil {
			return nil, err
		}
		if err := fdnotifier.AddFD(int32(ownedFD), queue); err != nil {
			return nil, err
		}
	}
	return &descriptor{
		donated:    donated,
		origFD:     origFD,
		wouldBlock: wouldBlock,
		value:      ownedFD,
	}, nil
}

// initAfterLoad initializes the value of the descriptor after Load.
func (d *descriptor) initAfterLoad(mo *superOperations, id uint64, queue *waiter.Queue) error {
	if d.donated {
		var err error
		d.value, err = syscall.Dup(d.origFD)
		if err != nil {
			return fmt.Errorf("failed to dup restored fd %d: %v", d.origFD, err)
		}
	} else {
		name, ok := mo.inodeMappings[id]
		if !ok {
			return fmt.Errorf("failed to find path for inode number %d", id)
		}
		fullpath := path.Join(mo.root, name)

		var err error
		d.value, err = open(nil, fullpath)
		if err != nil {
			return fmt.Errorf("failed to open %q: %v", fullpath, err)
		}
	}
	if d.wouldBlock {
		if err := syscall.SetNonblock(d.value, true); err != nil {
			return err
		}
		if err := fdnotifier.AddFD(int32(d.value), queue); err != nil {
			return err
		}
	}
	return nil
}

// Release releases all resources held by descriptor.
func (d *descriptor) Release() {
	if d.wouldBlock {
		fdnotifier.RemoveFD(int32(d.value))
	}
	if err := syscall.Close(d.value); err != nil {
		log.Warningf("error closing fd %d: %v", d.value, err)
	}
	d.value = -1
}
