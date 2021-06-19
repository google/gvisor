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
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
)

var sockHeaderLen uint32 = uint32((*sockHeader)(nil).SizeBytes())

// sockCommunicator implements Communicator. This is not thread safe.
type sockCommunicator struct {
	sock *unet.Socket
	buf  []byte
}

var _ Communicator = (*sockCommunicator)(nil)

func newSockComm(sock *unet.Socket) *sockCommunicator {
	return &sockCommunicator{
		sock: sock,
		buf:  make([]byte, sockHeaderLen),
	}
}

func (s *sockCommunicator) FD() int {
	return s.sock.FD()
}

func (s *sockCommunicator) destroy() {
	s.sock.Close()
	s.buf = s.buf[:0]
}

func (s *sockCommunicator) shutdown() {
	if err := s.sock.Shutdown(); err != nil {
		log.Warningf("Socket.Shutdown() failed (FD: %d): %v", s.sock.FD(), err)
	}
}

func (s *sockCommunicator) resizeBuf(size uint32) {
	if cap(s.buf) < int(size) {
		s.buf = s.buf[:cap(s.buf)]
		s.buf = append(s.buf, make([]byte, int(size)-cap(s.buf))...)
	} else {
		s.buf = s.buf[:size]
	}
}

// PayloadBuf implements Communicator.PayloadBuf.
func (s *sockCommunicator) PayloadBuf(size uint32) []byte {
	s.resizeBuf(sockHeaderLen + size)
	return s.buf[sockHeaderLen : sockHeaderLen+size]
}

// sndPrepopulatedMsg assumes that s.buf has already been populated with
// `payloadLen` bytes of data.
func (s *sockCommunicator) sndPrepopulatedMsg(m MID, payloadLen uint32, fds []int) error {
	header := sockHeader{size: sockHeaderLen + payloadLen, message: m}
	header.MarshalUnsafe(s.buf)
	return writeTo(s.sock, [][]byte{s.buf[:header.size]}, int(header.size), fds)
}

// sndMsg writes the header followed by the message payload to the UDS.
func (s *sockCommunicator) sndMsg(m MID, msgSize uint32, msgMarshal func(dst []byte), fds []int) error {
	header := sockHeader{size: sockHeaderLen, message: m}
	if msgMarshal != nil {
		header.size += msgSize
		if header.size > MaxMessageSize {
			log.Warningf("message size too big: %d", header.size)
			return unix.EINVAL
		}
		s.resizeBuf(header.size)
		// The payload goes right after the header.
		msgMarshal(s.buf[sockHeaderLen : sockHeaderLen+msgSize])
	}
	header.MarshalUnsafe(s.buf)

	return writeTo(s.sock, [][]byte{s.buf[:header.size]}, int(header.size), fds)
}

// writeTo writes the passed iovec to the UDS and donates any passed FDs. Note
// that FD donation is destructive: the passed fds are closed after donation.
func writeTo(sock *unet.Socket, iovec [][]byte, dataLen int, fds []int) error {
	w := sock.Writer(true)
	if len(fds) > 0 {
		defer closeFDs(fds)
		w.PackFDs(fds...)
	}

	for n := 0; n < dataLen; {
		cur, err := w.WriteVec(iovec)
		if err != nil {
			return err
		}
		n += cur

		// Consume iovecs.
		for consumed := 0; consumed < cur; {
			if len(iovec[0]) <= cur-consumed {
				consumed += len(iovec[0])
				iovec = iovec[1:]
			} else {
				iovec[0] = iovec[0][cur-consumed:]
				break
			}
		}

		if n > 0 && n < dataLen {
			// Don't resend any control message.
			w.UnpackFDs()
		}
	}
	return nil
}

// rcvMsg reads the message header and payload from the UDS. It also populates
// fds with any donated FDs.
func (s *sockCommunicator) rcvMsg(fds []int) (MID, uint32, error) {
	if err := readFrom(s.sock, s.buf[:sockHeaderLen], fds); err != nil {
		return 0, 0, err
	}

	var header sockHeader
	header.UnmarshalUnsafe(s.buf)

	if header.size < sockHeaderLen || header.size > MaxMessageSize {
		log.Warningf("inappropriate message size specified in header: %d", header.size)
		return 0, 0, unix.EINVAL
	}

	// No payload? We are done.
	if header.size == sockHeaderLen {
		return header.message, 0, nil
	}

	if err := readFrom(s.sock, s.PayloadBuf(header.size-sockHeaderLen), nil); err != nil {
		return 0, 0, err
	}

	return header.message, header.size - sockHeaderLen, nil
}

// readFrom fills the passed buffer with data from the socket. It also returns
// any donated FDs.
func readFrom(sock *unet.Socket, buf []byte, fds []int) error {
	r := sock.Reader(true)
	r.EnableFDs(len(fds))

	// Set all FDs to -1 which indicates that the FD is not set.
	for i := 0; i < len(fds); i++ {
		fds[i] = -1
	}

	var fdInit bool
	n := len(buf)
	var got int
	for got < n {
		cur, err := r.ReadVec([][]byte{buf[got:]})

		// Ignore EOF if cur > 0.
		if err != nil && (err != io.EOF || cur == 0) {
			r.CloseFDs()
			closeFDs(fds)
			return err
		}

		if !fdInit && cur > 0 {
			extractedFDs, err := r.ExtractFDs()
			if err != nil {
				return err
			}
			for i, fd := range extractedFDs {
				if i < len(fds) {
					fds[i] = fd
				} else {
					log.Warningf("closing the %d FD recieved on channel because its extra", i+1)
					unix.Close(fd)
				}
			}
			fdInit = true
			r.EnableFDs(0)
		}

		got += cur
	}
	return nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}
