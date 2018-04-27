// Copyright 2018 Google Inc.
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
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/unet"
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
	New: func() interface{} {
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
	tagPool pool

	// fidPool is the collection of available fids.
	fidPool pool

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

	// messageSize is the maximum total size of a message.
	messageSize uint32

	// payloadSize is the maximum payload size of a read or write
	// request.  For large reads and writes this means that the
	// read or write is broken up into buffer-size/payloadSize
	// requests.
	payloadSize uint32

	// version is the agreed upon version X of 9P2000.L.Google.X.
	// version 0 implies 9P2000.L.
	version uint32
}

// NewClient creates a new client.  It performs a Tversion exchange with
// the server to assert that messageSize is ok to use.
//
// You should not use the same socket for multiple clients.
func NewClient(socket *unet.Socket, messageSize uint32, version string) (*Client, error) {
	// Need at least one byte of payload.
	if messageSize <= largestFixedSize {
		return nil, &ErrMessageTooLarge{
			size:  messageSize,
			msize: largestFixedSize,
		}
	}
	// Compute a payload size and round to 512 (normal block size)
	// if it's larger than a single block.
	payloadSize := messageSize - largestFixedSize
	if payloadSize > 512 && payloadSize%512 != 0 {
		payloadSize -= (payloadSize % 512)
	}
	c := &Client{
		socket:      socket,
		tagPool:     pool{start: 1, limit: uint64(NoTag)},
		fidPool:     pool{start: 1, limit: uint64(NoFID)},
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
		rversion := Rversion{}
		err := c.sendRecv(&Tversion{Version: versionString(requested), MSize: messageSize}, &rversion)

		// The server told us to try again with a lower version.
		if err == syscall.EAGAIN {
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
	return c, nil
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

// sendRecv performs a roundtrip message exchange.
//
// This is called by internal functions.
func (c *Client) sendRecv(t message, r message) error {
	tag, ok := c.tagPool.Get()
	if !ok {
		return ErrOutOfTags
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
		return err
	}

	// Co-ordinate with other receivers.
	if err := c.waitAndRecv(resp.done); err != nil {
		return err
	}

	// Is it an error message?
	//
	// For convenience, we transform these directly
	// into errors. Handlers need not handle this case.
	if rlerr, ok := resp.r.(*Rlerror); ok {
		return syscall.Errno(rlerr.Error)
	}

	// At this point, we know it matches.
	//
	// Per recv call above, we will only allow a type
	// match (and give our r) or an instance of Rlerror.
	return nil
}

// Version returns the negotiated 9P2000.L.Google version number.
func (c *Client) Version() uint32 {
	return c.version
}
