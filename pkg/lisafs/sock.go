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
	"io"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/unet"
)

var (
	sockHeaderLen = uint32((*sockHeader)(nil).SizeBytes())
)

// sockHeader is the header present in front of each message received on a UDS.
//
// +marshal
type sockHeader struct {
	payloadLen uint32
	message    MID
	_          uint16 // Need to make struct packed.
}

// sockCommunicator implements Communicator. This is not thread safe.
type sockCommunicator struct {
	fdTracker
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

// SndRcvMessage implements Communicator.SndRcvMessage.
func (s *sockCommunicator) SndRcvMessage(m MID, payloadLen uint32, wantFDs uint8) (MID, uint32, error) {
	if err := s.sndPrepopulatedMsg(m, payloadLen, nil); err != nil {
		return 0, 0, err
	}

	return s.rcvMsg(wantFDs)
}

// String implements fmt.Stringer.String.
func (s *sockCommunicator) String() string {
	return fmt.Sprintf("sockComm %d", s.sock.FD())
}

// sndPrepopulatedMsg assumes that s.buf has already been populated with
// `payloadLen` bytes of data.
func (s *sockCommunicator) sndPrepopulatedMsg(m MID, payloadLen uint32, fds []int) error {
	header := sockHeader{payloadLen: payloadLen, message: m}
	header.MarshalUnsafe(s.buf)
	dataLen := sockHeaderLen + payloadLen
	return writeTo(s.sock, [][]byte{s.buf[:dataLen]}, int(dataLen), fds)
}

// writeTo writes the passed iovec to the UDS and donates any passed FDs.
func writeTo(sock *unet.Socket, iovec [][]byte, dataLen int, fds []int) error {
	w := sock.Writer(true)
	if len(fds) > 0 {
		w.PackFDs(fds...)
	}

	fdsUnpacked := false
	for n := 0; n < dataLen; {
		cur, err := w.WriteVec(iovec)
		if err != nil {
			return err
		}
		n += cur

		// Fast common path.
		if n >= dataLen {
			break
		}

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

		if n > 0 && !fdsUnpacked {
			// Don't resend any control message.
			fdsUnpacked = true
			w.UnpackFDs()
		}
	}
	return nil
}

// rcvMsg reads the message header and payload from the UDS. It also populates
// fds with any donated FDs.
func (s *sockCommunicator) rcvMsg(wantFDs uint8) (MID, uint32, error) {
	fds, err := readFrom(s.sock, s.buf[:sockHeaderLen], wantFDs)
	if err != nil {
		return 0, 0, err
	}
	for _, fd := range fds {
		s.TrackFD(fd)
	}

	var header sockHeader
	header.UnmarshalUnsafe(s.buf)

	// No payload? We are done.
	if header.payloadLen == 0 {
		return header.message, 0, nil
	}

	if _, err := readFrom(s.sock, s.PayloadBuf(header.payloadLen), 0); err != nil {
		return 0, 0, err
	}

	return header.message, header.payloadLen, nil
}

// readFrom fills the passed buffer with data from the socket. It also returns
// any donated FDs.
func readFrom(sock *unet.Socket, buf []byte, wantFDs uint8) ([]int, error) {
	r := sock.Reader(true)
	r.EnableFDs(int(wantFDs))

	var (
		fds    []int
		fdInit bool
	)
	n := len(buf)
	for got := 0; got < n; {
		cur, err := r.ReadVec([][]byte{buf[got:]})

		// Ignore EOF if cur > 0.
		if err != nil && (err != io.EOF || cur == 0) {
			r.CloseFDs()
			return nil, err
		}

		if !fdInit && cur > 0 {
			fds, err = r.ExtractFDs()
			if err != nil {
				return nil, err
			}

			fdInit = true
			r.EnableFDs(0)
		}

		got += cur
	}
	return fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			unix.Close(fd)
		}
	}
}
