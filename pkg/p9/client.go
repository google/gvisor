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

package p9

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/pool"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// ErrOutOfTags indicates no tags are available.
var ErrOutOfTags = errors.New("out of tags -- messages lost?")

// ErrOutOfFIDs indicates no more FIDs are available.
var ErrOutOfFIDs = errors.New("out of FIDs -- messages lost?")

// ErrUnexpectedTag indicates a response with an unexpected tag was received.
var ErrUnexpectedTag = errors.New("unexpected tag in response")

// ErrVersionsExhausted indicates that all versions to negotiate have been exhausted.
var ErrVersionsExhausted = errors.New("exhausted all versions to negotiate")

// ErrBadVersionString indicates that the version string is malformed or unsupported.
var ErrBadVersionString = errors.New("bad version string")

// ErrBadResponse indicates the response didn't match the request.
type ErrBadResponse struct {
	Got  MsgType
	Want MsgType
}

// Error returns a highly descriptive error.
func (e *ErrBadResponse) Error() string {
	return fmt.Sprintf("unexpected message type: got %v, want %v", e.Got, e.Want)
}

// response is the asynchronous return from recv.
//
// This is used in the pending map below.
type response struct {
	r    message
	done chan error
}

var responsePool = sync.Pool{
	New: func() any {
		return &response{
			done: make(chan error, 1),
		}
	},
}

// Client is at least a 9P2000.L client.
type Client struct {
	// socket is the connected socket.
	socket *unet.Socket

	// tagPool is the collection of available tags.
	tagPool pool.Pool

	// fidPool is the collection of available fids.
	fidPool pool.Pool

	// messageSize is the maximum total size of a message.
	messageSize uint32

	// payloadSize is the maximum payload size of a read or write.
	//
	// For large reads and writes this means that the read or write is
	// broken up into buffer-size/payloadSize requests.
	payloadSize uint32

	// version is the agreed upon version X of 9P2000.L.Google.X.
	// version 0 implies 9P2000.L.
	version uint32

	// closedWg is marked as done when the Client.watch() goroutine, which is
	// responsible for closing channels and the socket fd, returns.
	closedWg sync.WaitGroup

	// sendRecv is the transport function.
	//
	// This is determined dynamically based on whether or not the server
	// supports flipcall channels (preferred as it is faster and more
	// efficient, and does not require tags).
	sendRecv func(message, message) error

	//	-- below corresponds to sendRecvChannel --

	// channelsMu protects channels.
	channelsMu sync.Mutex

	// channelsWg counts the number of channels for which channel.active ==
	// true.
	channelsWg sync.WaitGroup

	// channels is the set of all initialized channels.
	channels []*channel

	// availableChannels is a LIFO of inactive channels.
	availableChannels []*channel

	//	-- below corresponds to sendRecvLegacy --

	// pending is the set of pending messages.
	pending   map[Tag]*response
	pendingMu sync.Mutex

	// sendMu is the lock for sending a request.
	sendMu sync.Mutex

	// recvr is essentially a mutex for calling recv.
	//
	// Whoever writes to this channel is permitted to call recv. When
	// finished calling recv, this channel should be emptied.
	recvr chan bool
}

// NewClient creates a new client.  It performs a Tversion exchange with
// the server to assert that messageSize is ok to use.
//
// If NewClient succeeds, ownership of socket is transferred to the new Client.
func NewClient(socket *unet.Socket, messageSize uint32, version string) (*Client, error) {
	// Need at least one byte of payload.
	if messageSize <= msgRegistry.largestFixedSize {
		return nil, &ErrMessageTooLarge{
			size:  messageSize,
			msize: msgRegistry.largestFixedSize,
		}
	}

	// Compute a payload size and round to 512 (normal block size)
	// if it's larger than a single block.
	payloadSize := messageSize - msgRegistry.largestFixedSize
	if payloadSize > 512 && payloadSize%512 != 0 {
		payloadSize -= (payloadSize % 512)
	}
	c := &Client{
		socket:      socket,
		tagPool:     pool.Pool{Start: 1, Limit: uint64(NoTag)},
		fidPool:     pool.Pool{Start: 1, Limit: uint64(NoFID)},
		pending:     make(map[Tag]*response),
		recvr:       make(chan bool, 1),
		messageSize: messageSize,
		payloadSize: payloadSize,
	}
	// Agree upon a version.
	requested, ok := parseVersion(version)
	if !ok {
		return nil, ErrBadVersionString
	}
	for {
		// Always exchange the version using the legacy version of the
		// protocol. If the protocol supports flipcall, then we switch
		// our sendRecv function to use that functionality.  Otherwise,
		// we stick to sendRecvLegacy.
		rversion := Rversion{}
		_, err := c.sendRecvLegacy(&Tversion{
			Version: versionString(requested),
			MSize:   messageSize,
		}, &rversion)

		// The server told us to try again with a lower version.
		if err == unix.EAGAIN {
			if requested == lowestSupportedVersion {
				return nil, ErrVersionsExhausted
			}
			requested--
			continue
		}

		// We requested an impossible version or our other parameters were bogus.
		if err != nil {
			return nil, err
		}

		// Parse the version.
		version, ok := parseVersion(rversion.Version)
		if !ok {
			// The server gave us a bad version. We return a generically worrisome error.
			log.Warningf("server returned bad version string %q", rversion.Version)
			return nil, ErrBadVersionString
		}
		c.version = version
		break
	}

	// Can we switch to use the more advanced channels and create
	// independent channels for communication? Prefer it if possible.
	if versionSupportsFlipcall(c.version) {
		// Attempt to initialize IPC-based communication.
		for i := 0; i < channelsPerClient; i++ {
			if err := c.openChannel(i); err != nil {
				log.Warningf("error opening flipcall channel: %v", err)
				break // Stop.
			}
		}
		if len(c.channels) >= 1 {
			// At least one channel created.
			c.sendRecv = c.sendRecvChannel
		} else {
			// Channel setup failed; fallback.
			c.sendRecv = c.sendRecvLegacySyscallErr
		}
	} else {
		// No channels available: use the legacy mechanism.
		c.sendRecv = c.sendRecvLegacySyscallErr
	}

	// Ensure that the socket and channels are closed when the socket is shut
	// down.
	c.closedWg.Add(1)
	go c.watch(socket) // S/R-SAFE: not relevant.

	return c, nil
}

// watch watches the given socket and releases resources on hangup events.
//
// This is intended to be called as a goroutine.
func (c *Client) watch(socket *unet.Socket) {
	defer c.closedWg.Done()

	events := []unix.PollFd{
		{
			Fd:     int32(socket.FD()),
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
			log.Warningf("p9.Client.watch(): %v", err)
			break
		}
		if n != 1 {
			log.Warningf("p9.Client.watch(): got %d events, wanted 1", n)
		}
		break
	}

	// Set availableChannels to nil so that future calls to c.sendRecvChannel()
	// don't attempt to activate a channel, and concurrent calls to
	// c.sendRecvChannel() don't mark released channels as available.
	c.channelsMu.Lock()
	c.availableChannels = nil

	// Shut down all active channels.
	for _, ch := range c.channels {
		if ch.active {
			log.Debugf("shutting down active channel@%p...", ch)
			ch.Shutdown()
		}
	}
	c.channelsMu.Unlock()

	// Wait for active channels to become inactive.
	c.channelsWg.Wait()

	// Close all channels.
	c.channelsMu.Lock()
	for _, ch := range c.channels {
		ch.Close()
	}
	c.channelsMu.Unlock()

	// Close the main socket.
	c.socket.Close()
}

// openChannel attempts to open a client channel.
//
// Note that this function returns naked errors which should not be propagated
// directly to a caller. It is expected that the errors will be logged and a
// fallback path will be used instead.
func (c *Client) openChannel(id int) error {
	var (
		rchannel0 Rchannel
		rchannel1 Rchannel
		res       = new(channel)
	)

	// Open the data channel.
	if _, err := c.sendRecvLegacy(&Tchannel{
		ID:      uint32(id),
		Control: 0,
	}, &rchannel0); err != nil {
		return fmt.Errorf("error handling Tchannel message: %v", err)
	}
	if rchannel0.FilePayload() == nil {
		return fmt.Errorf("missing file descriptor on primary channel")
	}

	// We don't need to hold this.
	defer rchannel0.FilePayload().Close()

	// Open the channel for file descriptors.
	if _, err := c.sendRecvLegacy(&Tchannel{
		ID:      uint32(id),
		Control: 1,
	}, &rchannel1); err != nil {
		return err
	}
	if rchannel1.FilePayload() == nil {
		return fmt.Errorf("missing file descriptor on file descriptor channel")
	}

	// Construct the endpoints.
	res.desc = flipcall.PacketWindowDescriptor{
		FD:     rchannel0.FilePayload().FD(),
		Offset: int64(rchannel0.Offset),
		Length: int(rchannel0.Length),
	}
	if err := res.data.Init(flipcall.ClientSide, res.desc); err != nil {
		rchannel1.FilePayload().Close()
		return err
	}

	// The fds channel owns the control payload, and it will be closed when
	// the channel object is closed.
	res.fds.Init(rchannel1.FilePayload().Release())

	// Save the channel.
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	c.channels = append(c.channels, res)
	c.availableChannels = append(c.availableChannels, res)
	return nil
}

// handleOne handles a single incoming message.
//
// This should only be called with the token from recvr. Note that the received
// tag will automatically be cleared from pending.
func (c *Client) handleOne() {
	tag, r, err := recv(c.socket, c.messageSize, func(tag Tag, t MsgType) (message, error) {
		c.pendingMu.Lock()
		resp := c.pending[tag]
		c.pendingMu.Unlock()

		// Not expecting this message?
		if resp == nil {
			log.Warningf("client received unexpected tag %v, ignoring", tag)
			return nil, ErrUnexpectedTag
		}

		// Is it an error? We specifically allow this to
		// go through, and then we deserialize below.
		if t == MsgRlerror {
			return &Rlerror{}, nil
		}

		// Does it match expectations?
		if t != resp.r.Type() {
			return nil, &ErrBadResponse{Got: t, Want: resp.r.Type()}
		}

		// Return the response.
		return resp.r, nil
	})

	if err != nil {
		// No tag was extracted (probably a socket error).
		//
		// Likely catastrophic. Notify all waiters and clear pending.
		c.pendingMu.Lock()
		for _, resp := range c.pending {
			resp.done <- err
		}
		c.pending = make(map[Tag]*response)
		c.pendingMu.Unlock()
	} else {
		// Process the tag.
		//
		// We know that is is contained in the map because our lookup function
		// above must have succeeded (found the tag) to return nil err.
		c.pendingMu.Lock()
		resp := c.pending[tag]
		delete(c.pending, tag)
		c.pendingMu.Unlock()
		resp.r = r
		resp.done <- err
	}
}

// waitAndRecv co-ordinates with other receivers to handle responses.
func (c *Client) waitAndRecv(done chan error) error {
	for {
		select {
		case err := <-done:
			return err
		case c.recvr <- true:
			select {
			case err := <-done:
				// It's possible that we got the token, despite
				// done also being available. Check for that.
				<-c.recvr
				return err
			default:
				// Handle receiving one tag.
				c.handleOne()

				// Return the token.
				<-c.recvr
			}
		}
	}
}

// sendRecvLegacySyscallErr is a wrapper for sendRecvLegacy that converts all
// non-syscall errors to EIO.
func (c *Client) sendRecvLegacySyscallErr(t message, r message) error {
	received, err := c.sendRecvLegacy(t, r)
	if !received {
		log.Warningf("p9.Client.sendRecvChannel: %v", err)
		return unix.EIO
	}
	return err
}

// sendRecvLegacy performs a roundtrip message exchange.
//
// sendRecvLegacy returns true if a message was received. This allows us to
// differentiate between failed receives and successful receives where the
// response was an error message.
//
// This is called by internal functions.
func (c *Client) sendRecvLegacy(t message, r message) (bool, error) {
	tag, ok := c.tagPool.Get()
	if !ok {
		return false, ErrOutOfTags
	}
	defer c.tagPool.Put(tag)

	// Indicate we're expecting a response.
	//
	// Note that the tag will be cleared from pending
	// automatically (see handleOne for details).
	resp := responsePool.Get().(*response)
	defer responsePool.Put(resp)
	resp.r = r
	c.pendingMu.Lock()
	c.pending[Tag(tag)] = resp
	c.pendingMu.Unlock()

	// Send the request over the wire.
	c.sendMu.Lock()
	err := send(c.socket, Tag(tag), t)
	c.sendMu.Unlock()
	if err != nil {
		return false, err
	}

	// Co-ordinate with other receivers.
	if err := c.waitAndRecv(resp.done); err != nil {
		return false, err
	}

	// Is it an error message?
	//
	// For convenience, we transform these directly
	// into errors. Handlers need not handle this case.
	if rlerr, ok := resp.r.(*Rlerror); ok {
		return true, unix.Errno(rlerr.Error)
	}

	// At this point, we know it matches.
	//
	// Per recv call above, we will only allow a type
	// match (and give our r) or an instance of Rlerror.
	return true, nil
}

// sendRecvChannel uses channels to send a message.
func (c *Client) sendRecvChannel(t message, r message) error {
	// Acquire an available channel.
	c.channelsMu.Lock()
	if len(c.availableChannels) == 0 {
		c.channelsMu.Unlock()
		return c.sendRecvLegacySyscallErr(t, r)
	}
	idx := len(c.availableChannels) - 1
	ch := c.availableChannels[idx]
	c.availableChannels = c.availableChannels[:idx]
	ch.active = true
	c.channelsWg.Add(1)
	c.channelsMu.Unlock()

	// Ensure that it's connected.
	if !ch.connected {
		ch.connected = true
		if err := ch.data.Connect(); err != nil {
			// The channel is unusable, so don't return it to
			// c.availableChannels. However, we still have to mark it as
			// inactive so c.watch() doesn't wait for it.
			c.channelsMu.Lock()
			ch.active = false
			c.channelsMu.Unlock()
			c.channelsWg.Done()
			// Map all transport errors to EIO, but ensure that the real error
			// is logged.
			log.Warningf("p9.Client.sendRecvChannel: flipcall.Endpoint.Connect: %v", err)
			return unix.EIO
		}
	}

	// Send the request and receive the server's response.
	rsz, err := ch.send(t, false /* isServer */)
	if err != nil {
		// See above.
		c.channelsMu.Lock()
		ch.active = false
		c.channelsMu.Unlock()
		c.channelsWg.Done()
		log.Warningf("p9.Client.sendRecvChannel: p9.channel.send: %v", err)
		return unix.EIO
	}

	// Parse the server's response.
	resp, retErr := ch.recv(r, rsz)
	if resp == nil {
		log.Warningf("p9.Client.sendRecvChannel: p9.channel.recv: %v", retErr)
		retErr = unix.EIO
	}

	// Release the channel.
	c.channelsMu.Lock()
	ch.active = false
	// If c.availableChannels is nil, c.watch() has fired and we should not
	// mark this channel as available.
	if c.availableChannels != nil {
		c.availableChannels = append(c.availableChannels, ch)
	}
	c.channelsMu.Unlock()
	c.channelsWg.Done()

	return retErr
}

// Version returns the negotiated 9P2000.L.Google version number.
func (c *Client) Version() uint32 {
	return c.version
}

// Close closes the underlying socket and channels.
func (c *Client) Close() {
	// unet.Socket.Shutdown() has no effect if unet.Socket.Close() has already
	// been called (by c.watch()).
	if err := c.socket.Shutdown(); err != nil {
		log.Warningf("Socket.Shutdown() failed (FD: %d): %v", c.socket.FD(), err)
	}
	c.closedWg.Wait()
}
