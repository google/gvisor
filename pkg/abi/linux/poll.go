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

package linux

// PollFD is struct pollfd, used by poll(2)/ppoll(2), from uapi/asm-generic/poll.h.
type PollFD struct {
	FD      int32
	Events  int16
	REvents int16
}

// Poll event flags, used by poll(2)/ppoll(2) and/or
// epoll_ctl(2)/epoll_wait(2), from uapi/asm-generic/poll.h.
const (
	POLLIN         = 0x0001
	POLLPRI        = 0x0002
	POLLOUT        = 0x0004
	POLLERR        = 0x0008
	POLLHUP        = 0x0010
	POLLNVAL       = 0x0020
	POLLRDNORM     = 0x0040
	POLLRDBAND     = 0x0080
	POLLWRNORM     = 0x0100
	POLLWRBAND     = 0x0200
	POLLMSG        = 0x0400
	POLLREMOVE     = 0x1000
	POLLRDHUP      = 0x2000
	POLLFREE       = 0x4000
	POLL_BUSY_LOOP = 0x8000
)
