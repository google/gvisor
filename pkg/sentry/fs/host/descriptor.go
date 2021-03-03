// Copyright 2018 The gVisor Authors.
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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/waiter"
)

// descriptor wraps a host fd.
//
// +stateify savable
type descriptor struct {
	// If origFD >= 0, it is the host fd that this file was originally created
	// from, which must be available at time of restore. The FD can be closed
	// after descriptor is created.
	origFD int

	// wouldBlock is true if value (below) points to a file that can
	// return EWOULDBLOCK for operations that would block.
	wouldBlock bool

	// value is the wrapped host fd. It is never saved or restored
	// directly.
	value int `state:"nosave"`
}

// newDescriptor returns a wrapped host file descriptor. On success,
// the descriptor is registered for event notifications with queue.
func newDescriptor(fd int, saveable bool, wouldBlock bool, queue *waiter.Queue) (*descriptor, error) {
	ownedFD := fd
	origFD := -1
	if saveable {
		var err error
		ownedFD, err = unix.Dup(fd)
		if err != nil {
			return nil, err
		}
		origFD = fd
	}
	if wouldBlock {
		if err := unix.SetNonblock(ownedFD, true); err != nil {
			return nil, err
		}
		if err := fdnotifier.AddFD(int32(ownedFD), queue); err != nil {
			return nil, err
		}
	}
	return &descriptor{
		origFD:     origFD,
		wouldBlock: wouldBlock,
		value:      ownedFD,
	}, nil
}

// initAfterLoad initializes the value of the descriptor after Load.
func (d *descriptor) initAfterLoad(id uint64, queue *waiter.Queue) error {
	var err error
	d.value, err = unix.Dup(d.origFD)
	if err != nil {
		return fmt.Errorf("failed to dup restored fd %d: %v", d.origFD, err)
	}
	if d.wouldBlock {
		if err := unix.SetNonblock(d.value, true); err != nil {
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
	if err := unix.Close(d.value); err != nil {
		log.Warningf("error closing fd %d: %v", d.value, err)
	}
	d.value = -1
}
