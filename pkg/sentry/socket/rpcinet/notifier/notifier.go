// Copyright 2018 Google LLC
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

// Package notifier implements an FD notifier implementation over RPC.
package notifier

import (
	"fmt"
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/conn"
	pb "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/syscall_rpc_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

type fdInfo struct {
	queue   *waiter.Queue
	waiting bool
}

// Notifier holds all the state necessary to issue notifications when IO events
// occur in the observed FDs.
type Notifier struct {
	// rpcConn is the connection that is used for sending RPCs.
	rpcConn *conn.RPCConnection

	// epFD is the epoll file descriptor used to register for io
	// notifications.
	epFD uint32

	// mu protects fdMap.
	mu sync.Mutex

	// fdMap maps file descriptors to their notification queues and waiting
	// status.
	fdMap map[uint32]*fdInfo
}

// NewRPCNotifier creates a new notifier object.
func NewRPCNotifier(cn *conn.RPCConnection) (*Notifier, error) {
	id, c := cn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_EpollCreate1{&pb.EpollCreate1Request{}}}, false /* ignoreResult */)
	<-c

	res := cn.Request(id).Result.(*pb.SyscallResponse_EpollCreate1).EpollCreate1.Result
	if e, ok := res.(*pb.EpollCreate1Response_ErrorNumber); ok {
		return nil, syscall.Errno(e.ErrorNumber)
	}

	w := &Notifier{
		rpcConn: cn,
		epFD:    res.(*pb.EpollCreate1Response_Fd).Fd,
		fdMap:   make(map[uint32]*fdInfo),
	}

	go w.waitAndNotify() // S/R-FIXME(b/77962828)

	return w, nil
}

// waitFD waits on mask for fd. The fdMap mutex must be hold.
func (n *Notifier) waitFD(fd uint32, fi *fdInfo, mask waiter.EventMask) error {
	if !fi.waiting && mask == 0 {
		return nil
	}

	e := pb.EpollEvent{
		Events: mask.ToLinux() | -syscall.EPOLLET,
		Fd:     fd,
	}

	switch {
	case !fi.waiting && mask != 0:
		id, c := n.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_EpollCtl{&pb.EpollCtlRequest{Epfd: n.epFD, Op: syscall.EPOLL_CTL_ADD, Fd: fd, Event: &e}}}, false /* ignoreResult */)
		<-c

		e := n.rpcConn.Request(id).Result.(*pb.SyscallResponse_EpollCtl).EpollCtl.ErrorNumber
		if e != 0 {
			return syscall.Errno(e)
		}

		fi.waiting = true
	case fi.waiting && mask == 0:
		id, c := n.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_EpollCtl{&pb.EpollCtlRequest{Epfd: n.epFD, Op: syscall.EPOLL_CTL_DEL, Fd: fd}}}, false /* ignoreResult */)
		<-c
		n.rpcConn.Request(id)

		fi.waiting = false
	case fi.waiting && mask != 0:
		id, c := n.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_EpollCtl{&pb.EpollCtlRequest{Epfd: n.epFD, Op: syscall.EPOLL_CTL_MOD, Fd: fd, Event: &e}}}, false /* ignoreResult */)
		<-c

		e := n.rpcConn.Request(id).Result.(*pb.SyscallResponse_EpollCtl).EpollCtl.ErrorNumber
		if e != 0 {
			return syscall.Errno(e)
		}
	}

	return nil
}

// addFD adds an FD to the list of FDs observed by n.
func (n *Notifier) addFD(fd uint32, queue *waiter.Queue) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Panic if we're already notifying on this FD.
	if _, ok := n.fdMap[fd]; ok {
		panic(fmt.Sprintf("File descriptor %d added twice", fd))
	}

	// We have nothing to wait for at the moment. Just add it to the map.
	n.fdMap[fd] = &fdInfo{queue: queue}
}

// updateFD updates the set of events the FD needs to be notified on.
func (n *Notifier) updateFD(fd uint32) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if fi, ok := n.fdMap[fd]; ok {
		return n.waitFD(fd, fi, fi.queue.Events())
	}

	return nil
}

// RemoveFD removes an FD from the list of FDs observed by n.
func (n *Notifier) removeFD(fd uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Remove from map, then from epoll object.
	n.waitFD(fd, n.fdMap[fd], 0)
	delete(n.fdMap, fd)
}

// hasFD returns true if the FD is in the list of observed FDs.
func (n *Notifier) hasFD(fd uint32) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	_, ok := n.fdMap[fd]
	return ok
}

// waitAndNotify loops waiting for io event notifications from the epoll
// object. Once notifications arrive, they are dispatched to the
// registered queue.
func (n *Notifier) waitAndNotify() error {
	for {
		id, c := n.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_EpollWait{&pb.EpollWaitRequest{Fd: n.epFD, NumEvents: 100, Msec: -1}}}, false /* ignoreResult */)
		<-c

		res := n.rpcConn.Request(id).Result.(*pb.SyscallResponse_EpollWait).EpollWait.Result
		if e, ok := res.(*pb.EpollWaitResponse_ErrorNumber); ok {
			err := syscall.Errno(e.ErrorNumber)
			// NOTE(magi): I don't think epoll_wait can return EAGAIN but I'm being
			// conseratively careful here since exiting the notification thread
			// would be really bad.
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return err
		}

		n.mu.Lock()
		for _, e := range res.(*pb.EpollWaitResponse_Events).Events.Events {
			if fi, ok := n.fdMap[e.Fd]; ok {
				fi.queue.Notify(waiter.EventMaskFromLinux(e.Events))
			}
		}
		n.mu.Unlock()
	}
}

// AddFD adds an FD to the list of observed FDs.
func (n *Notifier) AddFD(fd uint32, queue *waiter.Queue) error {
	n.addFD(fd, queue)
	return nil
}

// UpdateFD updates the set of events the FD needs to be notified on.
func (n *Notifier) UpdateFD(fd uint32) error {
	return n.updateFD(fd)
}

// RemoveFD removes an FD from the list of observed FDs.
func (n *Notifier) RemoveFD(fd uint32) {
	n.removeFD(fd)
}

// HasFD returns true if the FD is in the list of observed FDs.
//
// This should only be used by tests to assert that FDs are correctly
// registered.
func (n *Notifier) HasFD(fd uint32) bool {
	return n.hasFD(fd)
}

// NonBlockingPoll polls the given fd in non-blocking fashion. It is used just
// to query the FD's current state; this method will block on the RPC response
// although the syscall is non-blocking.
func (n *Notifier) NonBlockingPoll(fd uint32, mask waiter.EventMask) waiter.EventMask {
	for {
		id, c := n.rpcConn.NewRequest(pb.SyscallRequest{Args: &pb.SyscallRequest_Poll{&pb.PollRequest{Fd: fd, Events: mask.ToLinux()}}}, false /* ignoreResult */)
		<-c

		res := n.rpcConn.Request(id).Result.(*pb.SyscallResponse_Poll).Poll.Result
		if e, ok := res.(*pb.PollResponse_ErrorNumber); ok {
			if syscall.Errno(e.ErrorNumber) == syscall.EINTR {
				continue
			}
			return mask
		}

		return waiter.EventMaskFromLinux(res.(*pb.PollResponse_Events).Events)
	}
}
