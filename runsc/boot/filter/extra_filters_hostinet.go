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
	rules := seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_ACCEPT4: seccomp.PerArg{
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC),
		},
		unix.SYS_BIND:        seccomp.MatchAll{},
		unix.SYS_CONNECT:     seccomp.MatchAll{},
		unix.SYS_GETPEERNAME: seccomp.MatchAll{},
		unix.SYS_GETSOCKNAME: seccomp.MatchAll{},
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFCONF),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCETHTOOL),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFFLAGS),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFHWADDR),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFINDEX),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFMTU),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFNAME),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.SIOCGIFNETMASK),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.TIOCOUTQ),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(unix.TIOCINQ),
			},
		},
		unix.SYS_LISTEN:   seccomp.MatchAll{},
		unix.SYS_READV:    seccomp.MatchAll{},
		unix.SYS_RECVFROM: seccomp.MatchAll{},
		unix.SYS_RECVMSG:  seccomp.MatchAll{},
		unix.SYS_SENDMSG:  seccomp.MatchAll{},
		unix.SYS_SENDTO:   seccomp.MatchAll{},
		unix.SYS_SHUTDOWN: seccomp.Or{
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SHUT_RD),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SHUT_WR),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SHUT_RDWR),
			},
		},
		unix.SYS_WRITEV: seccomp.MatchAll{},
	})

	// Need NETLINK_ROUTE and stream sockets to query host interfaces and
	// routes.
	socketRules := seccomp.Or{
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_NETLINK),
			seccomp.EqualTo(unix.SOCK_RAW | unix.SOCK_CLOEXEC),
			seccomp.EqualTo(unix.NETLINK_ROUTE),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET),
			seccomp.EqualTo(unix.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
		seccomp.PerArg{
			seccomp.EqualTo(unix.AF_INET6),
			seccomp.EqualTo(unix.SOCK_STREAM),
			seccomp.EqualTo(0),
		},
	}

	// Generate rules for socket creation based on hostinet's supported
	// socket types.
	stypes := hostinet.AllowedSocketTypes
	if allowRawSockets {
		stypes = append(stypes, hostinet.AllowedRawSocketTypes...)
	}
	for _, sock := range stypes {
		rule := seccomp.PerArg{
			seccomp.EqualTo(sock.Family),
			// We always set SOCK_NONBLOCK and SOCK_CLOEXEC.
			seccomp.EqualTo(sock.Type | linux.SOCK_NONBLOCK | linux.SOCK_CLOEXEC),
			// Match specific protocol by default.
			seccomp.EqualTo(sock.Protocol),
		}
		if sock.Protocol == hostinet.AllowAllProtocols {
			// Change protocol filter to MatchAny.
			rule[2] = seccomp.AnyValue{}
		}
		socketRules = append(socketRules, rule)
	}
	rules.Set(unix.SYS_SOCKET, socketRules)

	// Generate rules for socket options based on hostinet's supported
	// socket options.
	for _, opt := range hostinet.SockOpts {
		if opt.AllowGet {
			rules.Add(unix.SYS_GETSOCKOPT, seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(opt.Level),
				seccomp.EqualTo(opt.Name),
			})
		}
		if opt.AllowSet {
			if opt.Size > 0 {
				rules.Add(unix.SYS_SETSOCKOPT, seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.EqualTo(opt.Level),
					seccomp.EqualTo(opt.Name),
					seccomp.AnyValue{},
					seccomp.EqualTo(opt.Size),
				})
			} else {
				rules.Add(unix.SYS_SETSOCKOPT, seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.EqualTo(opt.Level),
					seccomp.EqualTo(opt.Name),
				})
			}
		}
	}

	return rules
}
