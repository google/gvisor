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
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/eventfd"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
)

type serverRx struct {
	// packetPipe represents the receive end of the pipe that carries the packet
	// descriptors sent by the client.
	packetPipe pipe.Rx

	// completionPipe represents the transmit end of the pipe that will carry
	// completion notifications from the server to the client.
	completionPipe pipe.Tx

	// data represents the buffer area where the packet payload is held.
	data []byte

	// eventFD is used to notify the peer when transmission is completed.
	eventFD eventfd.Eventfd

	// sharedData the memory region to use to enable/disable notifications.
	sharedData []byte
}

// init initializes all state needed by the serverTx queue based on the
// information provided.
//
// The caller always retains ownership of all file descriptors passed in. The
// queue implementation will duplicate any that it may need in the future.
func (s *serverRx) init(c *QueueConfig) error {
	// Map in all buffers.
	packetPipeMem, err := getBuffer(c.TxPipeFD)
	if err != nil {
		return err
	}
	cu := cleanup.Make(func() { unix.Munmap(packetPipeMem) })
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

	s.packetPipe.Init(packetPipeMem)
	s.completionPipe.Init(completionPipeMem)
	s.data = data
	s.eventFD = efd
	s.sharedData = sharedData

	cu.Release()
	return nil
}

func (s *serverRx) cleanup() {
	unix.Munmap(s.packetPipe.Bytes())
	unix.Munmap(s.completionPipe.Bytes())
	unix.Munmap(s.data)
	unix.Munmap(s.sharedData)
	s.eventFD.Close()
}

// completionNotificationSize is size in bytes of a completion notification sent
// on the completion queue after a transmitted packet has been handled.
const completionNotificationSize = 8

// receive receives a single packet from the packetPipe.
func (s *serverRx) receive() []byte {
	desc := s.packetPipe.Pull()
	if desc == nil {
		return nil
	}

	pktInfo := queue.DecodeTxPacketHeader(desc)
	contents := make([]byte, 0, pktInfo.Size)
	toCopy := pktInfo.Size
	for i := 0; i < pktInfo.BufferCount; i++ {
		txBuf := queue.DecodeTxBufferHeader(desc, i)
		if txBuf.Size <= toCopy {
			contents = append(contents, s.data[txBuf.Offset:][:txBuf.Size]...)
			toCopy -= txBuf.Size
			continue
		}
		contents = append(contents, s.data[txBuf.Offset:][:toCopy]...)
		break
	}

	// Flush to let peer know that slots queued for transmission have been handled
	// and its free to reuse the slots.
	s.packetPipe.Flush()
	// Encode packet completion.
	b := s.completionPipe.Push(completionNotificationSize)
	queue.EncodeTxCompletion(b, pktInfo.ID)
	s.completionPipe.Flush()
	return contents
}

func (s *serverRx) waitForPackets() {
	s.eventFD.Wait()
}
