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

// Package netfilter helps the sentry interact with netstack's netfilter
// capabilities.
package netfilter

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// GetInfo returns information about iptables.
func GetInfo(t *kernel.Task, ep tcpip.Endpoint, outPtr usermem.Addr) (linux.IPTGetinfo, *syserr.Error) {
	// TODO(b/129292233): Implement.
	return linux.IPTGetinfo{}, syserr.ErrInvalidArgument
}

// GetEntries returns netstack's iptables rules encoded for the iptables tool.
func GetEntries(t *kernel.Task, ep tcpip.Endpoint, outPtr usermem.Addr, outLen int) (linux.KernelIPTGetEntries, *syserr.Error) {
	// TODO(b/129292233): Implement.
	return linux.KernelIPTGetEntries{}, syserr.ErrInvalidArgument
}

// FillDefaultIPTables sets stack's IPTables to the default tables and
// populates them with metadata.
func FillDefaultIPTables(stack *stack.Stack) error {
	stack.SetIPTables(iptables.DefaultTables())
	return nil
}
