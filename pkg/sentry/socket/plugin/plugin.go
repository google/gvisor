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

// Package plugin provides a set of interfaces to interact with
// third-party netstack. It will be used during sandbox network setup when
// NetworkType is set as NetworkPlugin.
package plugin

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/waiter"
)

// PluginStack defines a set of stack operations to work with a third-party
// plugin stack.
type PluginStack interface {
	inet.Stack

	// Init initializes plugin stack.
	Init(args *InitStackArgs) error

	// PreInit handles prepare steps before initializing plugin stack.
	// It may include joining namespace, mounting NIC, etc.
	PreInit(args *PreInitStackArgs) (string, []int, error)
}

// InitStackArgs is a struct that holds arguments needed by PluginStack.Init.
type InitStackArgs struct {
	// InitStr represents arguments needed to initialize plugin stack.
	InitStr string

	// FDs represents files opened during stack pre-init stage, which will
	// be used in stack initialization.
	FDs []int
}

// PreInitStackArgs is a struct that holds arguments needed by
// PluginStack.PreInit.
type PreInitStackArgs struct {
	// Pid represents current process that invokes plugin stack
	// pre-init.
	Pid int
}

var pluginStack PluginStack

// RegisterPluginStack registers given stack as plugin stack.
func RegisterPluginStack(stack PluginStack) {
	if pluginStack != nil {
		panic("called RegisterPluginStack more than once")
	}
	pluginStack = stack
}

// GetPluginStack fetches the current registered plugin stack.
func GetPluginStack() PluginStack {
	return pluginStack
}

// EventInfo holds a socket's notification queue and readiness cache.
//
// Mask and Waiting are protected by the owning notifier's mutex. EventInfo
// does not retain that notifier, so checklocks cannot express these guards.
type EventInfo struct {
	// Wq is the socket's event queue, initialized before registration.
	// The pointer is immutable; the queue synchronizes its own entries.
	Wq *waiter.Queue

	// Mask represents events this socket registered.
	Mask waiter.EventMask

	// Ready caches reported events. The notifier updates it concurrently with
	// socket readiness checks, which consume cached IN/OUT events.
	//
	// +checkatomic
	Ready atomicbitops.Uint64

	// Waiting is the notifier's record of whether this socket is registered
	// with the plugin stack's epoll instance.
	Waiting bool
}

// PluginNotifier represents a set of operations to handle
// plugin network stack's event notification mechanisms.
type PluginNotifier interface {
	// AddFD registers a socket fd and its event notification state with
	// the notifier.
	AddFD(fd uint32, eventinfo *EventInfo) error

	// RemoveFD unregisters a socket fd from the notifier.
	RemoveFD(fd uint32)

	// UpdateFD updates the set of events the socket fd needs
	// to be notified on.
	UpdateFD(fd uint32) error
}
