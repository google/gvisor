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
	"io"
	"io/ioutil"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
)

// ErrSocket is returned in cases of a socket issue.
//
// This may be treated differently than other errors.
type ErrSocket struct {
	// error is the socket error.
	error
}

// ErrMessageTooLarge indicates the size was larger than reasonable.
type ErrMessageTooLarge struct {
	size  uint32
	msize uint32
}

// Error returns a sensible error.
func (e *ErrMessageTooLarge) Error() string {
	return fmt.Sprintf("message too large for fixed buffer: size is %d, limit is %d", e.size, e.msize)
}

// ErrNoValidMessage indicates no valid message could be decoded.
var ErrNoValidMessage = errors.New("buffer contained no valid message")

const (
	// headerLength is the number of bytes required for a header.
	headerLength uint32 = 7

	// maximumLength is the largest possible message.
	maximumLength uint32 = 1 << 20

	// DefaultMessageSize is a sensible default.
	DefaultMessageSize uint32 = 64 << 10

	// initialBufferLength is the initial data buffer we allocate.
	initialBufferLength uint32 = 64
)

var dataPool = sync.Pool{
	New: func() interface{} {
		// These buffers are used for decoding without a payload.
		return make([]byte, initialBufferLength)
	},
}

// send sends the given message over the socket.
func send(s *unet.Socket, tag Tag, m message) error {
	data := dataPool.Get().([]byte)
	dataBuf := buffer{data: data[:0]}

	if log.IsLogging(log.Debug) {
		log.Debugf("send [FD %d] [Tag %06d] %s", s.FD(), tag, m.String())
	}

	// Encode the message. The buffer will grow automatically.
	m.Encode(&dataBuf)

	// Get our vectors to send.
	var hdr [headerLength]byte
	vecs := make([][]byte, 0, 3)
	vecs = append(vecs, hdr[:])
	if len(dataBuf.data) > 0 {
		vecs = append(vecs, dataBuf.data)
	}
	totalLength := headerLength + uint32(len(dataBuf.data))

	// Is there a payload?
	if payloader, ok := m.(payloader); ok {
		p := payloader.Payload()
		if len(p) > 0 {
			vecs = append(vecs, p)
			totalLength += uint32(len(p))
		}
	}

	// Construct the header.
	headerBuf := buffer{data: hdr[:0]}
	headerBuf.Write32(totalLength)
	headerBuf.WriteMsgType(m.Type())
	headerBuf.WriteTag(tag)

	// Pack any files if necessary.
	w := s.Writer(true)
	if filer, ok := m.(filer); ok {
		if f := filer.FilePayload(); f != nil {
			defer f.Close()
			// Pack the file into the message.
			w.PackFDs(f.FD())
		}
	}

	for n := 0; n < int(totalLength); {
		cur, err := w.WriteVec(vecs)
		if err != nil {
			return ErrSocket{err}
		}
		n += cur

		// Consume iovecs.
		for consumed := 0; consumed < cur; {
			if len(vecs[0]) <= cur-consumed {
				consumed += len(vecs[0])
				vecs = vecs[1:]
			} else {
				vecs[0] = vecs[0][cur-consumed:]
				break
			}
		}

		if n > 0 && n < int(totalLength) {
			// Don't resend any control message.
			w.UnpackFDs()
		}
	}

	// All set.
	dataPool.Put(dataBuf.data)
	return nil
}

// lookupTagAndType looks up an existing message or creates a new one.
//
// This is called by recv after decoding the header. Any error returned will be
// propagating back to the caller. You may use messageByType directly as a
// lookupTagAndType function (by design).
type lookupTagAndType func(tag Tag, t MsgType) (message, error)

// recv decodes a message from the socket.
//
// This is done in two parts, and is thus not safe for multiple callers.
//
// On a socket error, the special error type ErrSocket is returned.
//
// The tag value NoTag will always be returned if err is non-nil.
func recv(s *unet.Socket, msize uint32, lookup lookupTagAndType) (Tag, message, error) {
	// Read a header.
	//
	// Since the send above is atomic, we must always receive control
	// messages along with the header. This means we need to be careful
	// about closing FDs during errors to prevent leaks.
	var hdr [headerLength]byte
	r := s.Reader(true)
	r.EnableFDs(1)

	n, err := r.ReadVec([][]byte{hdr[:]})
	if err != nil && (n == 0 || err != io.EOF) {
		r.CloseFDs()
		return NoTag, nil, ErrSocket{err}
	}

	fds, err := r.ExtractFDs()
	if err != nil {
		return NoTag, nil, ErrSocket{err}
	}
	defer func() {
		// Close anything left open. The case where
		// fds are caught and used is handled below,
		// and the fds variable will be set to nil.
		for _, fd := range fds {
			syscall.Close(fd)
		}
	}()
	r.EnableFDs(0)

	// Continuing reading for a short header.
	for n < int(headerLength) {
		cur, err := r.ReadVec([][]byte{hdr[n:]})
		if err != nil && (cur == 0 || err != io.EOF) {
			return NoTag, nil, ErrSocket{err}
		}
		n += cur
	}

	// Decode the header.
	headerBuf := buffer{data: hdr[:]}
	size := headerBuf.Read32()
	t := headerBuf.ReadMsgType()
	tag := headerBuf.ReadTag()
	if size < headerLength {
		// The message is too small.
		//
		// See above: it's probably screwed.
		return NoTag, nil, ErrSocket{ErrNoValidMessage}
	}
	if size > maximumLength || size > msize {
		// The message is too big.
		return NoTag, nil, ErrSocket{&ErrMessageTooLarge{size, msize}}
	}
	remaining := size - headerLength

	// Find our message to decode.
	m, err := lookup(tag, t)
	if err != nil {
		// Throw away the contents of this message.
		if remaining > 0 {
			io.Copy(ioutil.Discard, &io.LimitedReader{R: s, N: int64(remaining)})
		}
		return tag, nil, err
	}

	// Not yet initialized.
	var dataBuf buffer

	// Read the rest of the payload.
	//
	// This requires some special care to ensure that the vectors all line
	// up the way they should. We do this to minimize copying data around.
	var vecs [][]byte
	if payloader, ok := m.(payloader); ok {
		fixedSize := payloader.FixedSize()

		// Do we need more than there is?
		if fixedSize > remaining {
			// This is not a valid message.
			if remaining > 0 {
				io.Copy(ioutil.Discard, &io.LimitedReader{R: s, N: int64(remaining)})
			}
			return NoTag, nil, ErrNoValidMessage
		}

		if fixedSize != 0 {
			// Pull a data buffer from the pool.
			data := dataPool.Get().([]byte)
			if int(fixedSize) > len(data) {
				// Create a larger data buffer, ensuring
				// sufficient capicity for the message.
				data = make([]byte, fixedSize)
				defer dataPool.Put(data)
				dataBuf = buffer{data: data}
				vecs = append(vecs, data)
			} else {
				// Limit the data buffer, and make sure it
				// gets filled before the payload buffer.
				defer dataPool.Put(data)
				dataBuf = buffer{data: data[:fixedSize]}
				vecs = append(vecs, data[:fixedSize])
			}
		}

		// Include the payload.
		p := payloader.Payload()
		if p == nil || len(p) != int(remaining-fixedSize) {
			p = make([]byte, remaining-fixedSize)
			payloader.SetPayload(p)
		}
		if len(p) > 0 {
			vecs = append(vecs, p)
		}
	} else if remaining != 0 {
		// Pull a data buffer from the pool.
		data := dataPool.Get().([]byte)
		if int(remaining) > len(data) {
			// Create a larger data buffer.
			data = make([]byte, remaining)
			defer dataPool.Put(data)
			dataBuf = buffer{data: data}
			vecs = append(vecs, data)
		} else {
			// Limit the data buffer.
			defer dataPool.Put(data)
			dataBuf = buffer{data: data[:remaining]}
			vecs = append(vecs, data[:remaining])
		}
	}

	if len(vecs) > 0 {
		// Read the rest of the message.
		//
		// No need to handle a control message.
		r := s.Reader(true)
		for n := 0; n < int(remaining); {
			cur, err := r.ReadVec(vecs)
			if err != nil && (cur == 0 || err != io.EOF) {
				return NoTag, nil, ErrSocket{err}
			}
			n += cur

			// Consume iovecs.
			for consumed := 0; consumed < cur; {
				if len(vecs[0]) <= cur-consumed {
					consumed += len(vecs[0])
					vecs = vecs[1:]
				} else {
					vecs[0] = vecs[0][cur-consumed:]
					break
				}
			}
		}
	}

	// Decode the message data.
	m.Decode(&dataBuf)
	if dataBuf.isOverrun() {
		// No need to drain the socket.
		return NoTag, nil, ErrNoValidMessage
	}

	// Save the file, if any came out.
	if filer, ok := m.(filer); ok && len(fds) > 0 {
		// Set the file object.
		filer.SetFilePayload(fd.New(fds[0]))

		// Close the rest. We support only one.
		for i := 1; i < len(fds); i++ {
			syscall.Close(fds[i])
		}

		// Don't close in the defer.
		fds = nil
	}

	if log.IsLogging(log.Debug) {
		log.Debugf("recv [FD %d] [Tag %06d] %s", s.FD(), tag, m.String())
	}

	// All set.
	return tag, m, nil
}
