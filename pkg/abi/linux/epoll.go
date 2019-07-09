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

// EpollEvent is equivalent to struct epoll_event from epoll(2).
type EpollEvent struct {
	Events uint32
	Fd     int32
	Data   int32
}

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
	EPOLLET      = 0x80000000
	EPOLLONESHOT = 0x40000000
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
