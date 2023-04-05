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

package filter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/socket/hostinet"
)

// hostInetFilters contains syscalls that are needed by sentry/socket/hostinet.
func hostInetFilters(allowRawSockets bool) seccomp.SyscallRules {
	rules := seccomp.SyscallRules{
		unix.SYS_ACCEPT4: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.MatchAny{},
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
			},
		},
		unix.SYS_BIND:        {},
		unix.SYS_CONNECT:     {},
		unix.SYS_GETPEERNAME: {},
		unix.SYS_GETSOCKNAME: {},
		unix.SYS_IOCTL: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.TIOCOUTQ),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.TIOCINQ),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SIOCGIFFLAGS),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SIOCGIFCONF),
			},
			// Needed to query netlink sockets.
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SIOCETHTOOL),
			},
		},
		unix.SYS_LISTEN:   {},
		unix.SYS_READV:    {},
		unix.SYS_RECVFROM: {},
		unix.SYS_RECVMSG:  {},
		unix.SYS_SENDMSG:  {},
		unix.SYS_SENDTO:   {},
		unix.SYS_SHUTDOWN: []seccomp.Rule{
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SHUT_RD),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SHUT_WR),
			},
			{
				seccomp.MatchAny{},
				seccomp.EqualTo(unix.SHUT_RDWR),
			},
		},
		unix.SYS_WRITEV: {},
	}

	// Generate rules for socket creation based on hostinet's supported
	// socket types.
	socketRules := []seccomp.Rule{
		// Need NETLINK_ROUTE and stream sockets to query host
		// interfaces and routes.
		seccomp.Rule{
			seccomp.EqualTo(unix.AF_NETLINK),
			seccomp.EqualTo(unix.SOCK_RAW | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(unix.NETLINK_ROUTE),
		},
		seccomp.Rule{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
		seccomp.Rule{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
	}

	stypes := hostinet.AllowedSocketTypes
	if allowRawSockets {
		stypes = append(stypes, hostinet.AllowedRawSocketTypes...)
	}
	for _, sock := range stypes {
		rule := seccomp.Rule{
			seccomp.EqualTo(sock.Family),
			// We always set SOCK_NONBLOCK and SOCK_CLOEXEC.
			seccomp.EqualTo(sock.Type | linux.SOCK_NONBLOCK | linux.SOCK_CLOEXEC),
			// Match specific protocol by default.
			seccomp.EqualTo(sock.Protocol),
		}
		if sock.Protocol == hostinet.AllowAllProtocols {
			// Change protocol filter to MatchAny.
			rule[2] = seccomp.MatchAny{}
		}
		socketRules = append(socketRules, rule)
	}
	rules[unix.SYS_SOCKET] = socketRules

	// Generate rules for socket options based on hostinet's supported
	// socket options.
	getSockOptRules := []seccomp.Rule{}
	setSockOptRules := []seccomp.Rule{}
	for _, opt := range hostinet.SockOpts {
		if opt.AllowGet {
			getSockOptRules = append(getSockOptRules, seccomp.Rule{
				seccomp.MatchAny{},
				seccomp.EqualTo(opt.Level),
				seccomp.EqualTo(opt.Name),
			})
		}
		if opt.AllowSet {
			if opt.Size > 0 {
				setSockOptRules = append(setSockOptRules, seccomp.Rule{
					seccomp.MatchAny{},
					seccomp.EqualTo(opt.Level),
					seccomp.EqualTo(opt.Name),
					seccomp.MatchAny{},
					seccomp.EqualTo(opt.Size),
				})
			} else {
				setSockOptRules = append(setSockOptRules, seccomp.Rule{
					seccomp.MatchAny{},
					seccomp.EqualTo(opt.Level),
					seccomp.EqualTo(opt.Name),
				})
			}
		}
	}
	rules[unix.SYS_GETSOCKOPT] = getSockOptRules
	rules[unix.SYS_SETSOCKOPT] = setSockOptRules

	return rules
}
