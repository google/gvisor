// Copyright 2019 The gVisor Authors.
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

package linux

// Event masks.
const (
	EPOLLIN     = 0x1
	EPOLLPRI    = 0x2
	EPOLLOUT    = 0x4
	EPOLLERR    = 0x8
	EPOLLHUP    = 0x10
	EPOLLRDNORM = 0x40
	EPOLLRDBAND = 0x80
	EPOLLWRNORM = 0x100
	EPOLLWRBAND = 0x200
	EPOLLMSG    = 0x400
	EPOLLRDHUP  = 0x2000
)

// Per-file descriptor flags.
const (
	EPOLLEXCLUSIVE = 1 << 28
	EPOLLWAKEUP    = 1 << 29
	EPOLLONESHOT   = 1 << 30
	EPOLLET        = 1 << 31

	// EP_PRIVATE_BITS is fs/eventpoll.c:EP_PRIVATE_BITS, the set of all bits
	// in an epoll event mask that correspond to flags rather than I/O events.
	EP_PRIVATE_BITS = EPOLLEXCLUSIVE | EPOLLWAKEUP | EPOLLONESHOT | EPOLLET
)

// Operation flags.
const (
	EPOLL_CLOEXEC  = 0x80000
	EPOLL_NONBLOCK = 0x800
)

// Control operations.
const (
	EPOLL_CTL_ADD = 0x1
	EPOLL_CTL_DEL = 0x2
	EPOLL_CTL_MOD = 0x3
)

// SizeOfEpollEvent is the size of EpollEvent struct.
var SizeOfEpollEvent = (*EpollEvent)(nil).SizeBytes()
