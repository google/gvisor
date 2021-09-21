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
	"math"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fdchannel"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
)

var (
	chanHeaderLen = uint32((*channelHeader)(nil).SizeBytes())
)

// maxChannels returns the number of channels a client can create.
//
// The server will reject channel creation requests beyond this (per client).
// Note that we don't want the number of channels to be too large, because each
// accounts for a large region of shared memory.
// TODO(gvisor.dev/issue/6313): Tune the number of channels.
func maxChannels() int {
	maxChans := runtime.GOMAXPROCS(0)
	if maxChans < 2 {
		maxChans = 2
	}
	if maxChans > 4 {
		maxChans = 4
	}
	return maxChans
}

// channel implements Communicator and represents the communication endpoint
// for the client and server and is used to perform fast IPC. Apart from
// communicating data, a channel is also capable of donating file descriptors.
type channel struct {
	fdTracker
	dead   bool
	data   flipcall.Endpoint
	fdChan fdchannel.Endpoint
}

var _ Communicator = (*channel)(nil)

// PayloadBuf implements Communicator.PayloadBuf.
func (ch *channel) PayloadBuf(size uint32) []byte {
	return ch.data.Data()[chanHeaderLen : chanHeaderLen+size]
}

// SndRcvMessage implements Communicator.SndRcvMessage.
func (ch *channel) SndRcvMessage(m MID, payloadLen uint32, wantFDs uint8) (MID, uint32, error) {
	// Write header. Requests can not donate FDs.
	ch.marshalHdr(m, 0 /* numFDs */)

	// One-shot communication. RPCs are expected to be quick rather than block.
	rcvDataLen, err := ch.data.SendRecvFast(chanHeaderLen + payloadLen)
	if err != nil {
		// This channel is now unusable.
		ch.dead = true
		// Map the transport errors to EIO, but also log the real error.
		log.Warningf("lisafs.sndRcvMessage: flipcall.Endpoint.SendRecv: %v", err)
		return 0, 0, unix.EIO
	}

	return ch.rcvMsg(rcvDataLen)
}

func (ch *channel) shutdown() {
	ch.data.Shutdown()
}

func (ch *channel) destroy() {
	ch.dead = true
	ch.fdChan.Destroy()
	ch.data.Destroy()
}

// createChannel creates a server side channel. It returns a packet window
// descriptor (for the data channel) and an open socket for the FD channel.
func (c *Connection) createChannel(maxMessageSize uint32) (*channel, flipcall.PacketWindowDescriptor, int, error) {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	// If c.channels is nil, the connection has closed.
	if c.channels == nil || len(c.channels) >= maxChannels() {
		return nil, flipcall.PacketWindowDescriptor{}, -1, unix.ENOSYS
	}
	ch := &channel{}

	// Set up data channel.
	desc, err := c.channelAlloc.Allocate(flipcall.PacketHeaderBytes + int(chanHeaderLen+maxMessageSize))
	if err != nil {
		return nil, flipcall.PacketWindowDescriptor{}, -1, err
	}
	if err := ch.data.Init(flipcall.ServerSide, desc); err != nil {
		return nil, flipcall.PacketWindowDescriptor{}, -1, err
	}

	// Set up FD channel.
	fdSocks, err := fdchannel.NewConnectedSockets()
	if err != nil {
		ch.data.Destroy()
		return nil, flipcall.PacketWindowDescriptor{}, -1, err
	}
	ch.fdChan.Init(fdSocks[0])
	clientFDSock := fdSocks[1]

	c.channels = append(c.channels, ch)
	return ch, desc, clientFDSock, nil
}

// sendFDs sends as many FDs as it can. The failure to send an FD does not
// cause an error and fail the entire RPC. FDs are considered supplementary
// responses that are not critical to the RPC response itself. The failure to
// send the (i)th FD will cause all the following FDs to not be sent as well
// because the order in which FDs are donated is important.
func (ch *channel) sendFDs(fds []int) uint8 {
	numFDs := len(fds)
	if numFDs == 0 {
		return 0
	}

	if numFDs > math.MaxUint8 {
		log.Warningf("dropping all FDs because too many FDs to donate: %v", numFDs)
		return 0
	}

	for i, fd := range fds {
		if err := ch.fdChan.SendFD(fd); err != nil {
			log.Warningf("error occurred while sending (%d/%d)th FD on channel(%p): %v", i+1, numFDs, ch, err)
			return uint8(i)
		}
	}
	return uint8(numFDs)
}

// channelHeader is the header present in front of each message received on
// flipcall endpoint when the protocol version being used is 1.
//
// +marshal
type channelHeader struct {
	message MID
	numFDs  uint8
	_       uint8 // Need to make struct packed.
}

func (ch *channel) marshalHdr(m MID, numFDs uint8) {
	header := &channelHeader{
		message: m,
		numFDs:  numFDs,
	}
	header.MarshalUnsafe(ch.data.Data())
}

func (ch *channel) rcvMsg(dataLen uint32) (MID, uint32, error) {
	if dataLen < chanHeaderLen {
		log.Warningf("received data has size smaller than header length: %d", dataLen)
		return 0, 0, unix.EIO
	}

	// Read header first.
	var header channelHeader
	header.UnmarshalUnsafe(ch.data.Data())

	// Read any FDs.
	for i := 0; i < int(header.numFDs); i++ {
		fd, err := ch.fdChan.RecvFDNonblock()
		if err != nil {
			log.Warningf("expected %d FDs, received %d successfully, got err after that: %v", header.numFDs, i, err)
			break
		}
		ch.TrackFD(fd)
	}

	return header.message, dataLen - chanHeaderLen, nil
}
