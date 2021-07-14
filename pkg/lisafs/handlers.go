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

package lisafs

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
)

// RPCHanlder defines a handler that the server implementation must define. The
// handler is responsible for:
// * Unmarshalling the request from the passed payload and interpreting it.
// * Marshalling the response into the communicator's payload buffer.
// * Return the number of payload bytes written along with any FDs to donate.
type RPCHanlder func(c *Connection, comm Communicator, payload []byte) (uint32, []int, error)

// ChannelHandler handles the Channel RPC.
func ChannelHandler(c *Connection, comm Communicator, payload []byte) (uint32, []int, error) {
	ch, desc, fdSock, err := c.createChannel()
	if err != nil {
		return 0, nil, err
	}

	// Start servicing the channel in a separate goroutine.
	c.activeWg.Add(1)
	go func() {
		if err := c.service(ch); err != nil {
			// Don't log shutdown error which is expected during server shutdown.
			if _, ok := err.(flipcall.ShutdownError); !ok {
				log.Warningf("lisafs.Connection.service(channel = @%p): %v", ch, err)
			}
		}
		c.activeWg.Done()
	}()

	clientDataFD, err := unix.Dup(desc.FD)
	if err != nil {
		unix.Close(fdSock)
		ch.shutdown()
		return 0, nil, err
	}

	// Respond to client with successful channel creation message.
	msg := &ChannelResp{
		dataOffset: desc.Offset,
		dataLength: uint64(desc.Length),
	}
	mSize := uint32(msg.SizeBytes())
	msg.MarshalBytes(comm.PayloadBuf(mSize))
	return mSize, []int{clientDataFD, fdSock}, nil
}

var _ RPCHanlder = ChannelHandler
