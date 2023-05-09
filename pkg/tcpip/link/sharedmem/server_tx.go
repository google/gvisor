// Copyright 2021 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// serverTx represents the server end of the sharedmem queue and is used to send
// packets to the peer in the buffers posted by the peer in the fillPipe.
type serverTx struct {
	// fillPipe represents the receive end of the pipe that carries the RxBuffers
	// posted by the peer.
	fillPipe pipe.Rx

	// completionPipe represents the transmit end of the pipe that carries the
	// descriptors for filled RxBuffers.
	completionPipe pipe.Tx

	// data represents the buffer area where the packet payload is held.
	data []byte

	// eventFD is used to notify the peer when fill requests are fulfilled.
	eventFD eventfd.Eventfd

	// sharedData the memory region to use to enable/disable notifications.
	sharedData []byte

	// sharedEventFDState is the memory region in sharedData used to enable/disable
	// notifications on eventFD.
	sharedEventFDState *atomicbitops.Uint32
}

// init initializes all tstate needed by the serverTx queue based on the
// information provided.
//
// The caller always retains ownership of all file descriptors passed in. The
// queue implementation will duplicate any that it may need in the future.
func (s *serverTx) init(c *QueueConfig) error {
	// Map in all buffers.
	fillPipeMem, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}
	cu := cleanup.Make(func() { unix.Munmap(fillPipeMem) })
	defer cu.Clean()

	completionPipeMem, err := getBuffer(c.RxPipeFD)
	if err != nil {
		return err
	}
	cu.Add(func() { unix.Munmap(completionPipeMem) })

	data, err := getBuffer(c.DataFD)
	if err != nil {
		return err
	}
	cu.Add(func() { unix.Munmap(data) })

	sharedData, err := getBuffer(c.SharedDataFD)
	if err != nil {
		return err
	}
	cu.Add(func() { unix.Munmap(sharedData) })

	// Duplicate the eventFD so that caller can close it but we can still
	// use it.
	efd, err := c.EventFD.Dup()
	if err != nil {
		return err
	}
	cu.Add(func() { efd.Close() })

	cu.Release()

	s.fillPipe.Init(fillPipeMem)
	s.completionPipe.Init(completionPipeMem)
	s.data = data
	s.eventFD = efd
	s.sharedData = sharedData
	s.sharedEventFDState = sharedDataPointer(sharedData)

	return nil
}

func (s *serverTx) cleanup() {
	unix.Munmap(s.fillPipe.Bytes())
	unix.Munmap(s.completionPipe.Bytes())
	unix.Munmap(s.data)
	unix.Munmap(s.sharedData)
	s.eventFD.Close()
}

// acquireBuffers acquires enough buffers to hold all the data in views or
// returns nil if not enough buffers are currently available.
func (s *serverTx) acquireBuffers(pktBuffer bufferv2.Buffer, buffers []queue.RxBuffer) (acquiredBuffers []queue.RxBuffer) {
	acquiredBuffers = buffers[:0]
	wantBytes := int(pktBuffer.Size())
	for wantBytes > 0 {
		var b []byte
		if b = s.fillPipe.Pull(); b == nil {
			s.fillPipe.Abort()
			return nil
		}
		rxBuffer := queue.DecodeRxBufferHeader(b)
		acquiredBuffers = append(acquiredBuffers, rxBuffer)
		wantBytes -= int(rxBuffer.Size)
	}
	return acquiredBuffers
}

// fillPacket copies the data in the provided views into buffers pulled from the
// fillPipe and returns a slice of RxBuffers that contain the copied data as
// well as the total number of bytes copied.
//
// To avoid allocations the filledBuffers are appended to the buffers slice
// which will be grown as required. This method takes ownership of pktBuffer.
func (s *serverTx) fillPacket(pktBuffer bufferv2.Buffer, buffers []queue.RxBuffer) (filledBuffers []queue.RxBuffer, totalCopied uint32) {
	bufs := s.acquireBuffers(pktBuffer, buffers)
	if bufs == nil {
		pktBuffer.Release()
		return nil, 0
	}
	br := pktBuffer.AsBufferReader()
	defer br.Close()

	for i := 0; br.Len() > 0 && i < len(bufs); i++ {
		buf := bufs[i]
		copied, err := br.Read(s.data[buf.Offset:][:buf.Size])
		buf.Size = uint32(copied)
		// Copy the packet into the posted buffer.
		totalCopied += bufs[i].Size
		if err != nil {
			return bufs, totalCopied
		}
	}
	return bufs, totalCopied
}

func (s *serverTx) transmit(pkt stack.PacketBufferPtr) bool {
	buffers := make([]queue.RxBuffer, 8)
	buffers, totalCopied := s.fillPacket(pkt.ToBuffer(), buffers)
	if totalCopied == 0 {
		// drop the packet as not enough buffers were probably available
		// to send.
		return false
	}
	b := s.completionPipe.Push(queue.RxCompletionSize(len(buffers)))
	if b == nil {
		return false
	}
	queue.EncodeRxCompletion(b, totalCopied, 0 /* reserved */)
	for i := 0; i < len(buffers); i++ {
		queue.EncodeRxCompletionBuffer(b, i, buffers[i])
	}
	s.completionPipe.Flush()
	s.fillPipe.Flush()
	return true
}

func (s *serverTx) notificationsEnabled() bool {
	// notifications are considered to be enabled unless explicitly disabled.
	return s.sharedEventFDState.Load() != queue.EventFDDisabled
}

func (s *serverTx) notify() {
	if s.notificationsEnabled() {
		s.eventFD.Notify()
	}
}
