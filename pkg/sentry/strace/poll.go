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

package strace

import (
	"fmt"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	slinux "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// PollEventSet is the set of poll(2) event flags.
var PollEventSet = abi.FlagSet{
	{Flag: linux.POLLIN, Name: "POLLIN"},
	{Flag: linux.POLLPRI, Name: "POLLPRI"},
	{Flag: linux.POLLOUT, Name: "POLLOUT"},
	{Flag: linux.POLLERR, Name: "POLLERR"},
	{Flag: linux.POLLHUP, Name: "POLLHUP"},
	{Flag: linux.POLLNVAL, Name: "POLLNVAL"},
	{Flag: linux.POLLRDNORM, Name: "POLLRDNORM"},
	{Flag: linux.POLLRDBAND, Name: "POLLRDBAND"},
	{Flag: linux.POLLWRNORM, Name: "POLLWRNORM"},
	{Flag: linux.POLLWRBAND, Name: "POLLWRBAND"},
	{Flag: linux.POLLMSG, Name: "POLLMSG"},
	{Flag: linux.POLLREMOVE, Name: "POLLREMOVE"},
	{Flag: linux.POLLRDHUP, Name: "POLLRDHUP"},
	{Flag: linux.POLLFREE, Name: "POLLFREE"},
	{Flag: linux.POLL_BUSY_LOOP, Name: "POLL_BUSY_LOOP"},
}

func pollFD(t *kernel.Task, pfd *linux.PollFD, post bool) string {
	revents := "..."
	if post {
		revents = PollEventSet.Parse(uint64(pfd.REvents))
	}
	return fmt.Sprintf("{FD: %s, Events: %s, REvents: %s}", fd(t, kdefs.FD(pfd.FD)), PollEventSet.Parse(uint64(pfd.Events)), revents)
}

func pollFDs(t *kernel.Task, addr usermem.Addr, nfds uint, post bool) string {
	if addr == 0 {
		return "null"
	}

	pfds, err := slinux.CopyInPollFDs(t, addr, nfds)
	if err != nil {
		return fmt.Sprintf("%#x (error decoding pollfds: %s)", addr, err)
	}

	s := make([]string, 0, len(pfds))
	for i := range pfds {
		s = append(s, pollFD(t, &pfds[i], post))
	}

	return fmt.Sprintf("%#x [%s]", addr, strings.Join(s, ", "))
}
