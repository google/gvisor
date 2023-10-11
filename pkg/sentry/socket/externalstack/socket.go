// Copyright 2023 The gVisor Authors.
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

package externalstack

import (
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sentry/stack"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type socketOperations struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.LockFD
	socket.SendReceiveTimeout
	*waiter.Queue

	family   int
	Endpoint tcpip.Endpoint
	skType   linux.SockType
	protocol int

	namespace *inet.Namespace

	// readMu protects access to the below fields.
	readMu sync.Mutex `state:"nosave"`

	// sockOptTimestamp corresponds to SO_TIMESTAMP. When true, timestamps
	// of returned messages can be returned via control messages. When
	// false, the same timestamp is instead stored and can be read via the
	// SIOCGSTAMP ioctl. It is protected by readMu. See socket(7).
	sockOptTimestamp bool

	// timestampValid indicates whether timestamp for SIOCGSTAMP has been
	// set. It is protected by readMu.
	timestampValid bool

	// timestamp holds the timestamp to use with SIOCTSTAMP. It is only
	// valid when timestampValid is true. It is protected by readMu.
	timestamp time.Time `state:".(int64)"`

	// sockOptInq corresponds to TCP_INQ.
	sockOptInq bool

	handle   uint32 `state:"nosave"`
	udpState uint32
	fi       stack.FdInfo
	notifier *ExternalNotifier `state:"nosave"`
	wq       *waiter.Queue
}

var _ = socket.Socket(&socketOperations{})

func (s *socketOperations) Bind(t *kernel.Task, sockaddr []byte) *syserr.Error {
	//TODO: implement glue layer
	return nil
}

func (s *socketOperations) Listen(t *kernel.Task, backlog int) *syserr.Error {
	//TODO: implement glue layer
	return nil
}

func (s *socketOperations) Accept(t *kernel.Task, peerRequested bool, flags int, blocking bool) (int32, linux.SockAddr, uint32, *syserr.Error) {
	//TODO: implement glue layer
	return 0, nil, 0, nil
}

func (s *socketOperations) Connect(t *kernel.Task, sockaddr []byte, blocking bool) *syserr.Error {
	//TODO: implement glue layer
	return nil
}

func (s *socketOperations) Shutdown(t *kernel.Task, how int) *syserr.Error {
	//TODO: implement glue layer
	return nil
}

func (s *socketOperations) GetSockOpt(t *kernel.Task, level int, name int, outPtr hostarch.Addr, outLen int) (marshal.Marshallable, *syserr.Error) {
	//TODO: implement glue layer
	return nil, nil
}

func (s *socketOperations) SetSockOpt(t *kernel.Task, level int, name int, optVal []byte) *syserr.Error {
	//TODO: implement glue layer
	return nil
}

func (s *socketOperations) RecvMsg(t *kernel.Task, dst usermem.IOSequence, flags int, haveDeadline bool, deadline ktime.Time, senderRequested bool, controlDataLen uint64) (int, int, linux.SockAddr, uint32, socket.ControlMessages, *syserr.Error) {
	//TODO: implement glue layer
	return 0, 0, nil, 0, socket.ControlMessages{}, syserr.ErrInvalidArgument
}

func (s *socketOperations) SendMsg(t *kernel.Task, src usermem.IOSequence, to []byte, flags int, haveDeadline bool, deadline ktime.Time, controlMessages socket.ControlMessages) (int, *syserr.Error) {
	//TODO: implement glue layer
	return 0, nil
}

func (s *socketOperations) State() uint32 {
	//TODO: implement glue layer
	return 0
}

func (s *socketOperations) Type() (family int, skType linux.SockType, protocol int) {
	//TODO: implement glue layer
	return 0, 0, 0
}

func (s *socketOperations) OnClose(ctx context.Context) error {
	return nil
}

func (s *socketOperations) EventRegister(e *waiter.Entry) error {
	//TODO: implement glue layer
	return nil
}

func (s *socketOperations) EventUnregister(e *waiter.Entry) {
	//TODO: implement glue layer
}

func (s *socketOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	//TODO: implement glue layer
	return 0
}

func (s *socketOperations) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	//TODO: implement glue layer
	return 0, nil
}

func (s *socketOperations) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	//TODO: implement glue layer
	return 0, nil
}

func (s *socketOperations) Epollable() bool {
	return true
}

func (s *socketOperations) Ioctl(ctx context.Context, io usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	//TODO: implement glue layer
	return 0, nil
}

func (s *socketOperations) Release(ctx context.Context) {
	//TODO: implement glue layer
}

func (s *socketOperations) GetSockName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	//TODO: implement glue layer
	return nil, 0, nil
}

func (s *socketOperations) GetPeerName(t *kernel.Task) (linux.SockAddr, uint32, *syserr.Error) {
	//TODO: implement glue layer
	return nil, 0, nil
}

func (s *socketOperations) saveTimestamp() int64 {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	return s.timestamp.UnixNano()
}

func (s *socketOperations) loadTimestamp(nsec int64) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.timestamp = time.Unix(0, nsec)
}
