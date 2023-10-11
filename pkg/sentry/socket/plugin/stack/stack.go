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

// Package stack provides an implementation of plugin.PluginStack
// interface and an implementation of socket.Socket interface.
//
// It glues sentry interfaces with plugin netstack interfaces defined in cgo.
package stack

import (
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin/cgo"
)

// Stack is a struct that interacts with third-party network stack.
// It implements inet.Stack and plugin.PluginStack.
type Stack struct {
	inet.Stack

	notifier *Notifier
}

var stack *Stack

// Init implements plugin.PluginStack.Init.
func (s *Stack) Init(args *plugin.InitStackArgs) error {
	if err := cgo.InitStack(args.InitStr, args.FDs); err != nil {
		return err
	}
	s.notifier = NewNotifier()
	stack = s
	return nil
}

// PreInit implements plugin.PluginStack.PreInit.
func (s *Stack) PreInit(args *plugin.PreInitStackArgs) (string, []int, error) {
	return cgo.PreInitStack(args.Pid)
}

// Interfaces implements inet.Stack.Interfaces.
func (s *Stack) Interfaces() map[int32]inet.Interface {
	// TODO: support Interfaces
	return make(map[int32]inet.Interface)
}

// InterfaceAddrs implements inet.Stack.InterfaceAddrs.
func (s *Stack) InterfaceAddrs() map[int32][]inet.InterfaceAddr {
	// TODO: support InterfaceAddrs
	return make(map[int32][]inet.InterfaceAddr)
}

// AddInterfaceAddr implements inet.Stack.AddInterfaceAddr.
func (s *Stack) AddInterfaceAddr(idx int32, addr inet.InterfaceAddr) error {
	return linuxerr.EACCES
}

// RemoveInterfaceAddr implements inet.Stack.RemoveInterfaceAddr.
func (s *Stack) RemoveInterfaceAddr(int32, inet.InterfaceAddr) error {
	return linuxerr.EACCES
}

// SupportsIPv6 implements Stack.SupportsIPv6.
func (s *Stack) SupportsIPv6() bool {
	return true
}

// Destroy implements inet.Stack.Destroy.
func (*Stack) Destroy() {
}

func init() {
	plugin.RegisterPluginStack(&Stack{})
}
