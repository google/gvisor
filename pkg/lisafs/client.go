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
	"math"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

const (
	// fdsToCloseBatchSize is the number of closed FDs batched before an Close
	// RPC is made to close them all. fdsToCloseBatchSize is immutable.
	fdsToCloseBatchSize = 100
)

// Client helps manage a connection to the lisafs server and pass messages
// efficiently. There is a 1:1 mapping between a Connection and a Client.
type Client struct {
	// sockComm is the main socket by which this connections is established.
	// Communication over the socket is synchronized by sockMu.
	sockMu   sync.Mutex
	sockComm *sockCommunicator

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

	// supported caches information about which messages are supported. It is
	// indexed by MID. An MID is supported if supported[MID] is true.
	supported []bool

	// maxMessageSize is the maximum payload length (in bytes) that can be sent.
	// It is initialized on Mount and is immutable.
	maxMessageSize uint32

	// fdsToClose tracks the FDs to close. It caches the FDs no longer being used
	// by the client and closes them in one shot. It is not preserved across
	// checkpoint/restore as FDIDs are not preserved.
	fdsMu      sync.Mutex
	fdsToClose []FDID
}

// NewClient creates a new client for communication with the server. It mounts
// the server and creates channels for fast IPC. NewClient takes ownership over
// the passed socket. On success, it returns the initialized client along with
// the root Inode.
func NewClient(sock *unet.Socket) (*Client, Inode, int, error) {
	c := &Client{
		sockComm:       newSockComm(sock),
		maxMessageSize: 1 << 20, // 1 MB for now.
		fdsToClose:     make([]FDID, 0, fdsToCloseBatchSize),
	}

	// Start a goroutine to check socket health. This goroutine is also
	// responsible for client cleanup.
	c.watchdogWg.Add(1)
	go c.watchdog()

	// Mount the server first. Assume Mount is supported so that we can make the
	// Mount RPC below.
	c.supported = make([]bool, Mount+1)
	c.supported[Mount] = true
	var (
		mountReq    MountReq
		mountResp   MountResp
		mountHostFD = [1]int{-1}
	)
	if err := c.SndRcvMessage(Mount, uint32(mountReq.SizeBytes()), mountReq.MarshalBytes, mountResp.CheckedUnmarshal, mountHostFD[:], mountReq.String, mountResp.String); err != nil {
		c.Close()
		return nil, Inode{}, -1, err
	}

	// Initialize client.
	c.maxMessageSize = uint32(mountResp.MaxMessageSize)
	var maxSuppMID MID
	for _, suppMID := range mountResp.SupportedMs {
		if suppMID > maxSuppMID {
			maxSuppMID = suppMID
		}
	}
	c.supported = make([]bool, maxSuppMID+1)
	for _, suppMID := range mountResp.SupportedMs {
		c.supported[suppMID] = true
	}
	return c, mountResp.Root, mountHostFD[0], nil
}

// StartChannels starts maxChannels() channel communicators.
func (c *Client) StartChannels() error {
	maxChans := maxChannels()
	c.channelsMu.Lock()
	c.channels = make([]*channel, 0, maxChans)
	c.availableChannels = make([]*channel, 0, maxChans)
	c.channelsMu.Unlock()

	// Create channels parallely so that channels can be used to create more
	// channels and costly initialization like flipcall.Endpoint.Connect can
	// proceed parallely.
	var channelsWg sync.WaitGroup
	for i := 0; i < maxChans; i++ {
		channelsWg.Add(1)
		go func() {
			defer channelsWg.Done()
			ch, err := c.createChannel()
			if err != nil {
				if err == unix.ENOMEM {
					log.Debugf("channel creation failed because server hit max channels limit")
				} else {
					log.Warningf("channel creation failed: %v", err)
				}
				return
			}
			c.channelsMu.Lock()
			c.channels = append(c.channels, ch)
			c.availableChannels = append(c.availableChannels, ch)
			c.channelsMu.Unlock()
		}()
	}
	channelsWg.Wait()

	// Check that atleast 1 channel is created. This is not required by lisafs
	// protocol. It exists to flag server side issues in channel creation.
	c.channelsMu.Lock()
	numChannels := len(c.channels)
	c.channelsMu.Unlock()
	if maxChans > 0 && numChannels == 0 {
		log.Warningf("all channel RPCs failed")
		return unix.ENOMEM
	}
	return nil
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
	var (
		chanReq  ChannelReq
		chanResp ChannelResp
	)
	var fds [2]int
	if err := c.SndRcvMessage(Channel, uint32(chanReq.SizeBytes()), chanReq.MarshalBytes, chanResp.CheckedUnmarshal, fds[:], chanReq.String, chanResp.String); err != nil {
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
	return int(m) < len(c.supported) && c.supported[m]
}

// CloseFD either queues the passed FD to be closed or makes a batch
// RPC to close all the accumulated FDs-to-close. If flush is true, the RPC
// is made immediately.
func (c *Client) CloseFD(ctx context.Context, fd FDID, flush bool) {
	c.fdsMu.Lock()
	c.fdsToClose = append(c.fdsToClose, fd)
	if !flush && len(c.fdsToClose) < fdsToCloseBatchSize {
		// We can continue batching.
		c.fdsMu.Unlock()
		return
	}

	// Flush the cache. We should not hold fdsMu while making an RPC, so be sure
	// to copy the fdsToClose to another buffer before unlocking fdsMu.
	var toCloseArr [fdsToCloseBatchSize]FDID
	toClose := toCloseArr[:len(c.fdsToClose)]
	copy(toClose, c.fdsToClose)

	// Clear fdsToClose so other FDIDs can be appended.
	c.fdsToClose = c.fdsToClose[:0]
	c.fdsMu.Unlock()

	req := CloseReq{FDs: toClose}
	var resp CloseResp
	ctx.UninterruptibleSleepStart(false)
	err := c.SndRcvMessage(Close, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil, req.String, resp.String)
	ctx.UninterruptibleSleepFinish(false)
	if err != nil {
		log.Warningf("lisafs: batch closing FDs returned error: %v", err)
	}
}

// SyncFDs makes a Fsync RPC to sync multiple FDs.
func (c *Client) SyncFDs(ctx context.Context, fds []FDID) error {
	if len(fds) == 0 {
		return nil
	}
	req := FsyncReq{FDs: fds}
	var resp FsyncResp
	ctx.UninterruptibleSleepStart(false)
	err := c.SndRcvMessage(FSync, uint32(req.SizeBytes()), req.MarshalBytes, resp.CheckedUnmarshal, nil, req.String, resp.String)
	ctx.UninterruptibleSleepFinish(false)
	return err
}

// SndRcvMessage invokes reqMarshal to marshal the request onto the payload
// buffer, wakes up the server to process the request, waits for the response
// and invokes respUnmarshal with the response payload. respFDs is populated
// with the received FDs, extra fields are set to -1.
//
// See messages.go to understand why function arguments are used instead of
// combining these functions into an interface type.
//
// Precondition: function arguments must be non-nil.
func (c *Client) SndRcvMessage(m MID, payloadLen uint32, reqMarshal marshalFunc, respUnmarshal unmarshalFunc, respFDs []int, reqString debugStringer, respString debugStringer) error {
	if !c.IsSupported(m) {
		return unix.EOPNOTSUPP
	}
	if payloadLen > c.maxMessageSize {
		log.Warningf("message %d has payload which is too large: %d bytes", m, payloadLen)
		return unix.EIO
	}
	wantFDs := len(respFDs)
	if wantFDs > math.MaxUint8 {
		log.Warningf("want too many FDs: %d", wantFDs)
		return unix.EINVAL
	}

	// Acquire a communicator.
	comm := c.acquireCommunicator()
	defer c.releaseCommunicator(comm)

	debugf("send", comm, reqString)

	// Marshal the request into comm's payload buffer and make the RPC.
	reqMarshal(comm.PayloadBuf(payloadLen))
	respM, respPayloadLen, err := comm.SndRcvMessage(m, payloadLen, uint8(wantFDs))

	// Handle FD donation.
	rcvFDs := comm.ReleaseFDs()
	if numRcvFDs := len(rcvFDs); numRcvFDs+wantFDs > 0 {
		// releasedFDs is memory owned by comm which can not be returned to caller.
		// Copy it into the caller's buffer.
		numFDCopied := copy(respFDs, rcvFDs)
		if numFDCopied < numRcvFDs {
			log.Warningf("%d unexpected FDs were donated by the server, wanted", numRcvFDs-numFDCopied, wantFDs)
			closeFDs(rcvFDs[numFDCopied:])
		}
		if numFDCopied < wantFDs {
			for i := numFDCopied; i < wantFDs; i++ {
				respFDs[i] = -1
			}
		}
	}

	// Error cases.
	if err != nil {
		closeFDs(respFDs)
		return err
	}
	if respPayloadLen > c.maxMessageSize {
		log.Warningf("server response for message %d is too large: %d bytes", respM, respPayloadLen)
		closeFDs(respFDs)
		return unix.EIO
	}
	if respM == Error {
		closeFDs(respFDs)
		var resp ErrorResp
		resp.UnmarshalUnsafe(comm.PayloadBuf(respPayloadLen))
		debugf("recv", comm, resp.String)
		return unix.Errno(resp.errno)
	}
	if respM != m {
		closeFDs(respFDs)
		log.Warningf("sent %d message but got %d in response", m, respM)
		return unix.EINVAL
	}

	// Success. The payload must be unmarshalled *before* comm is released.
	if _, ok := respUnmarshal(comm.PayloadBuf(respPayloadLen)); !ok {
		log.Warningf("server response unmarshalling for %d message failed", respM)
		return unix.EIO
	}
	debugf("recv", comm, respString)
	return nil
}

func debugf(action string, comm Communicator, debugMsg debugStringer) {
	// Replicate the log.IsLogging(log.Debug) check to avoid having to call
	// debugMsg() on the hot path.
	if log.IsLogging(log.Debug) {
		log.Debugf("%s [%s] %s", action, comm, debugMsg())
	}
}

// Postcondition: releaseCommunicator() must be called on the returned value.
func (c *Client) acquireCommunicator() Communicator {
	// Prefer using channel over socket because:
	//	- Channel uses a shared memory region for passing messages. IO from shared
	//		memory is faster and does not involve making a syscall.
	//	- No intermediate buffer allocation needed. With a channel, the message
	//		can be directly pasted into the shared memory region.
	if ch := c.getChannel(); ch != nil {
		return ch
	}

	c.sockMu.Lock()
	return c.sockComm
}

// Precondition: comm must have been acquired via acquireCommunicator().
func (c *Client) releaseCommunicator(comm Communicator) {
	switch t := comm.(type) {
	case *sockCommunicator:
		c.sockMu.Unlock() // +checklocksforce: locked in acquireCommunicator().
	case *channel:
		c.releaseChannel(t)
	default:
		panic(fmt.Sprintf("unknown communicator type %T", t))
	}
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
func (c *Client) releaseChannel(ch *channel) {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()

	// If availableChannels is nil, then watchdog has fired and the client is
	// shutting down. So don't make this channel available again.
	if !ch.dead && c.availableChannels != nil {
		c.availableChannels = append(c.availableChannels, ch)
	}
	c.activeWg.Done()
}
