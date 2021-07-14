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
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Client helps manage a connection to the lisafs server and pass messages
// efficiently. There is a 1:1 mapping between a Connection and a Client.
type Client struct {
	// sockComm is the main socket by which this connections is established.
	// Communication over the socket is synchronized by sockMu.
	sockComm *sockCommunicator
	sockMu   sync.Mutex

	// root is the file descriptor to the mount point on the server.
	root FDID

	// channelsMu protects channels and availableChannels.
	channelsMu sync.Mutex
	// channels tracks all the channels.
	channels []*channel
	// availableChannels is a LIFO (stack) of channels available to be used.
	availableChannels []*channel
	// activeWg represents active channels.
	activeWg sync.WaitGroup

	// watchdogWg only holds the watchdog goroutine.
	watchdogWg sync.WaitGroup

	// unsupported caches information about which messages are supported . It is
	// indexed by MID. An MID is unsupported if unsupported[MID] is true.
	unsupported []bool
}

// NewClient creates a new client for communication with the server. It mounts
// the server and creates channels for fast IPC. NewClient takes ownership over
// the passed socket.
func NewClient(sock *unet.Socket, mountPath string) (*Client, error) {
	c := &Client{
		sockComm:          newSockComm(sock),
		channels:          make([]*channel, 0, maxChannels),
		availableChannels: make([]*channel, 0, maxChannels),
	}

	// Mount the server first.
	mountMsg := MountReq{
		MountPath: SizedString{
			Str: mountPath,
		},
	}
	var mountResp MountResp
	if err := c.SndRcvMessage(Mount, &mountMsg, &mountResp, nil); err != nil {
		c.Close()
		return nil, err
	}

	// Initialise client.
	c.root = mountResp.Root
	c.unsupported = make([]bool, mountResp.MaxM+1)
	for _, unsupportedM := range mountResp.UnsupportedMs {
		if unsupportedM > mountResp.MaxM {
			panic(fmt.Sprintf("server responded with invalid unsupported message ID: %d", unsupportedM))
		}
		c.unsupported[unsupportedM] = true
	}

	// Create channels parallely so that channels can be used to create more
	// channels and costly initialization like flipcall.Endpoint.Connect can
	// proceed parallely.
	var channelsWg sync.WaitGroup
	for i := 0; i < maxChannels; i++ {
		channelsWg.Add(1)
		go func() {
			defer channelsWg.Done()
			ch, err := c.createChannel()
			if err != nil {
				log.Warningf("channel creation failed: %v", err)
				// This error is not a deal breaker. The client can at least
				// communicate using the healthy initialized socket.
				return
			}
			c.channelsMu.Lock()
			c.channels = append(c.channels, ch)
			c.availableChannels = append(c.availableChannels, ch)
			c.channelsMu.Unlock()
		}()
	}
	// TODO(ayushranjan): Should we even wait for this or just proceed.
	channelsWg.Wait()

	// Start a goroutine to check socket health.
	c.watchdogWg.Add(1)
	go c.watchdog()

	return c, nil
}

// Root returns the FD identifier for this client's mount root.
func (c *Client) Root() FDID {
	return c.root
}

func (c *Client) watchdog() {
	defer c.watchdogWg.Done()

	events := []unix.PollFd{
		{
			Fd:     int32(c.sockComm.FD()),
			Events: unix.POLLHUP | unix.POLLRDHUP,
		},
	}

	// Wait for a shutdown event.
	for {
		n, err := unix.Ppoll(events, nil, nil)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			log.Warningf("lisafs.Client.watch(): %v", err)
		} else if n != 1 {
			log.Warningf("lisafs.Client.watch(): got %d events, wanted 1", n)
		}
		break
	}

	// Shutdown all active channels and wait for them to complete.
	c.shutdownActiveChans()
	c.activeWg.Wait()

	// Close all channels.
	c.channelsMu.Lock()
	for _, ch := range c.channels {
		ch.destroy()
	}
	c.channelsMu.Unlock()

	// Close main socket.
	c.sockComm.destroy()
}

func (c *Client) shutdownActiveChans() {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()

	availableChans := make(map[*channel]bool)
	for _, ch := range c.availableChannels {
		availableChans[ch] = true
	}
	for _, ch := range c.channels {
		// A channel that is not available is active.
		if _, ok := availableChans[ch]; !ok {
			log.Debugf("shutting down active channel@%p...", ch)
			ch.shutdown()
		}
	}

	// Prevent channels from becoming available and serving new requests.
	c.availableChannels = nil
}

// Close shuts down the main socket and waits for the watchdog to clean up.
func (c *Client) Close() {
	// This shutdown has no effect if the watchdog has already fired and closed
	// the main socket.
	c.sockComm.shutdown()
	c.watchdogWg.Wait()
}

func (c *Client) createChannel() (*channel, error) {
	var chanResp ChannelResp
	var fds [2]int
	if err := c.SndRcvMessage(Channel, nil, &chanResp, fds[:]); err != nil {
		return nil, err
	}
	if fds[0] < 0 || fds[1] < 0 {
		closeFDs(fds[:])
		return nil, fmt.Errorf("insufficient FDs provided in Channel response: %v", fds)
	}

	// Lets create the channel.
	defer closeFDs(fds[:1]) // The data FD is not needed after this.
	desc := flipcall.PacketWindowDescriptor{
		FD:     fds[0],
		Offset: chanResp.dataOffset,
		Length: int(chanResp.dataLength),
	}

	ch := &channel{}
	if err := ch.data.Init(flipcall.ClientSide, desc); err != nil {
		closeFDs(fds[1:])
		return nil, err
	}
	ch.fdChan.Init(fds[1]) // fdChan now owns this FD.

	// Only a connected channel is usable.
	if err := ch.data.Connect(); err != nil {
		ch.destroy()
		return nil, err
	}
	return ch, nil
}

// IsSupported returns true if this connection supports the passed message.
func (c *Client) IsSupported(m MID) bool {
	return int(m) < len(c.unsupported) && !c.unsupported[m]
}

func checkResponse(reqM MID, respM MID, respBuf []byte) error {
	if respM == Error {
		var resp ErrorRes
		resp.UnmarshalBytes(respBuf)
		return unix.Errno(resp.errno)
	}
	if respM != reqM {
		log.Warningf("sent %d message but got %d in response", reqM, respM)
		return unix.EINVAL
	}
	return nil
}

// SndRcvMessage marshals the passed message, sends it over to the server,
// waits for the response and populates resp with the response. respFDs is
// populated with the donated FDs. len(respFDs) should be the expected number
// of donated FDs.
func (c *Client) SndRcvMessage(m MID, req marshal.Marshallable, resp marshal.Marshallable, respFDs []int) error {
	// Prefer using channel over socket because:
	// - Channel uses a shared memory region for passing messages. IO from shared
	//   memory is faster and does not involve making a syscall.
	// - No intermediate buffer allocation needed. With a channel, the message
	//   can be directly pasted into the shared memory region.
	if ch := c.getChannel(); ch != nil {
		reinsert := true
		defer c.releaseChannel(ch, &reinsert)

		sndDataLen, err := ch.marshalReq(m, req)
		if err != nil {
			return err
		}

		// One-shot communication.
		rcvDataLen, err := ch.data.SendRecv(sndDataLen)
		if err != nil {
			// This channel is unusable. Don't reinsert it.
			reinsert = false
			// Map the transport errors to EIO, but also log the real error.
			log.Warningf("lisafs.sndRcvMessage: flipcall.Endpoint.SendRecv: %v", err)
			return unix.EIO
		}

		respM, respBuf, err := ch.rcvMsg(rcvDataLen, respFDs)
		if err != nil {
			return err
		}
		if err := checkResponse(m, respM, respBuf); err != nil {
			return err
		}
		// The payload must be unmarshalled before the channel is released because
		// respBuf points to the channel's shared memory region. Do not refactor.
		if resp != nil {
			resp.UnmarshalBytes(respBuf)
		}
		return nil
	}

	// For now, only allow one thread to use this socket to send and receive.
	c.sockMu.Lock()
	defer c.sockMu.Unlock()
	if err := c.sockComm.sndMsg(m, req, nil); err != nil {
		return err
	}

	respM, respBuf, err := c.sockComm.rcvMsg(respFDs)
	if err != nil {
		return err
	}
	if err := checkResponse(m, respM, respBuf); err != nil {
		return err
	}
	if resp != nil {
		resp.UnmarshalBytes(respBuf)
	}
	return nil
}

// getChannel pops a channel from the available channels stack. The caller must
// release the channel after use.
func (c *Client) getChannel() *channel {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	if len(c.availableChannels) == 0 {
		return nil
	}

	idx := len(c.availableChannels) - 1
	ch := c.availableChannels[idx]
	c.availableChannels = c.availableChannels[:idx]
	c.activeWg.Add(1)
	return ch
}

// releaseChannel pushes the passed channel onto the available channel stack if
// reinsert is true.
func (c *Client) releaseChannel(ch *channel, reinsert *bool) {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	if *reinsert {
		// If availableChannels is nil, then watchdog has fired and the client is
		// shutting down. So don't make this channel available again.
		if c.availableChannels != nil {
			c.availableChannels = append(c.availableChannels, ch)
		}
	}
	c.activeWg.Done()
}
