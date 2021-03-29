// Copyright 2020 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func epollEvent(t *kernel.Task, eventAddr hostarch.Addr) string {
	var e linux.EpollEvent
	if _, err := e.CopyIn(t, eventAddr); err != nil {
		return fmt.Sprintf("%#x {error reading event: %v}", eventAddr, err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%#x ", eventAddr)
	writeEpollEvent(&sb, e)
	return sb.String()
}

func epollEvents(t *kernel.Task, eventsAddr hostarch.Addr, numEvents, maxBytes uint64) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%#x {", eventsAddr)
	addr := eventsAddr
	for i := uint64(0); i < numEvents; i++ {
		var e linux.EpollEvent
		if _, err := e.CopyIn(t, addr); err != nil {
			fmt.Fprintf(&sb, "{error reading event at %#x: %v}", addr, err)
			continue
		}
		writeEpollEvent(&sb, e)
		if uint64(sb.Len()) >= maxBytes {
			sb.WriteString("...")
			break
		}
		// Allowing addr to overflow is consistent with Linux, and harmless; if
		// this isn't the last iteration of the loop, the next call to CopyIn
		// will just fail with EFAULT.
		addr, _ = addr.AddLength(uint64(linux.SizeOfEpollEvent))
	}
	sb.WriteString("}")
	return sb.String()
}

func writeEpollEvent(sb *strings.Builder, e linux.EpollEvent) {
	events := epollEventEvents.Parse(uint64(e.Events))
	fmt.Fprintf(sb, "{events=%s data=[%#x, %#x]}", events, e.Data[0], e.Data[1])
}

var epollCtlOps = abi.ValueSet{
	linux.EPOLL_CTL_ADD: "EPOLL_CTL_ADD",
	linux.EPOLL_CTL_DEL: "EPOLL_CTL_DEL",
	linux.EPOLL_CTL_MOD: "EPOLL_CTL_MOD",
}

var epollEventEvents = abi.FlagSet{
	{Flag: linux.EPOLLIN, Name: "EPOLLIN"},
	{Flag: linux.EPOLLPRI, Name: "EPOLLPRI"},
	{Flag: linux.EPOLLOUT, Name: "EPOLLOUT"},
	{Flag: linux.EPOLLERR, Name: "EPOLLERR"},
	{Flag: linux.EPOLLHUP, Name: "EPOLLHUP"},
	{Flag: linux.EPOLLRDNORM, Name: "EPOLLRDNORM"},
	{Flag: linux.EPOLLRDBAND, Name: "EPOLLRDBAND"},
	{Flag: linux.EPOLLWRNORM, Name: "EPOLLWRNORM"},
	{Flag: linux.EPOLLWRBAND, Name: "EPOLLWRBAND"},
	{Flag: linux.EPOLLMSG, Name: "EPOLLMSG"},
	{Flag: linux.EPOLLRDHUP, Name: "EPOLLRDHUP"},
	{Flag: linux.EPOLLEXCLUSIVE, Name: "EPOLLEXCLUSIVE"},
	{Flag: linux.EPOLLWAKEUP, Name: "EPOLLWAKEUP"},
	{Flag: linux.EPOLLONESHOT, Name: "EPOLLONESHOT"},
	{Flag: linux.EPOLLET, Name: "EPOLLET"},
}
