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

//go:build linux
// +build linux

package sharedmem

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
)

// rx holds all state associated with an rx queue.
type rx struct {
	data       []byte
	sharedData []byte
	q          queue.Rx
	eventFD    eventfd.Eventfd
}

// init initializes all state needed by the rx queue based on the information
// provided.
//
// The caller always retains ownership of all file descriptors passed in. The
// queue implementation will duplicate any that it may need in the future.
func (r *rx) init(mtu uint32, c *QueueConfig) error {
	// Map in all buffers.
	txPipe, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}

	rxPipe, err := getBuffer(c.RxPipeFD)
	if err != nil {
		unix.Munmap(txPipe)
		return err
	}

	data, err := getBuffer(c.DataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		return err
	}

	sharedData, err := getBuffer(c.SharedDataFD)
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		unix.Munmap(data)
		return err
	}

	// Duplicate the eventFD so that caller can close it but we can still
	// use it.
	efd, err := c.EventFD.Dup()
	if err != nil {
		unix.Munmap(txPipe)
		unix.Munmap(rxPipe)
		unix.Munmap(data)
		unix.Munmap(sharedData)
		return err
	}

	// Initialize state based on buffers.
	r.q.Init(txPipe, rxPipe, sharedDataPointer(sharedData))
	r.data = data
	r.eventFD = efd
	r.sharedData = sharedData

	return nil
}

// cleanup releases all resources allocated during init() except r.eventFD. It
// must only be called if init() has previously succeeded.
func (r *rx) cleanup() {
	a, b := r.q.Bytes()
	unix.Munmap(a)
	unix.Munmap(b)

	unix.Munmap(r.data)
	unix.Munmap(r.sharedData)
}

// notify writes to the tx.eventFD to indicate to the peer that there is data to
// be read.
func (r *rx) notify() {
	r.eventFD.Notify()
}

// postAndReceive posts the provided buffers (if any), and then tries to read
// from the receive queue.
//
// Capacity permitting, it reuses the posted buffer slice to store the buffers
// that were read as well.
//
// This function will block if there aren't any available packets.
func (r *rx) postAndReceive(b []queue.RxBuffer, stopRequested *atomicbitops.Uint32) ([]queue.RxBuffer, uint32) {
	// Post the buffers first. If we cannot post, sleep until we can. We
	// never post more than will fit concurrently, so it's safe to wait
	// until enough room is available.
	if len(b) != 0 && !r.q.PostBuffers(b) {
		r.q.EnableNotification()
		for !r.q.PostBuffers(b) {
			r.eventFD.Wait()
			if stopRequested.Load() != 0 {
				r.q.DisableNotification()
				return nil, 0
			}
		}
		r.q.DisableNotification()
	}

	// Read the next set of descriptors.
	b, n := r.q.Dequeue(b[:0])
	if len(b) != 0 {
		return b, n
	}

	// Data isn't immediately available. Enable eventfd notifications.
	r.q.EnableNotification()
	for {
		b, n = r.q.Dequeue(b)
		if len(b) != 0 {
			break
		}

		// Wait for notification.
		r.eventFD.Wait()
		if stopRequested.Load() != 0 {
			r.q.DisableNotification()
			return nil, 0
		}
	}
	r.q.DisableNotification()

	return b, n
}
