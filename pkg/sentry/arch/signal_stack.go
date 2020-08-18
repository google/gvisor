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

// +build 386 amd64 arm64

package arch

import (
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

const (
	// SignalStackFlagOnStack is possible set on return from getaltstack,
	// in order to indicate that the thread is currently on the alt stack.
	SignalStackFlagOnStack = 1

	// SignalStackFlagDisable is a flag to indicate the stack is disabled.
	SignalStackFlagDisable = 2
)

// IsEnabled returns true iff this signal stack is marked as enabled.
func (s SignalStack) IsEnabled() bool {
	return s.Flags&SignalStackFlagDisable == 0
}

// Top returns the stack's top address.
func (s SignalStack) Top() usermem.Addr {
	return usermem.Addr(s.Addr + s.Size)
}

// SetOnStack marks this signal stack as in use.
//
// Note that there is no corresponding ClearOnStack, and that this should only
// be called on copies that are serialized to userspace.
func (s *SignalStack) SetOnStack() {
	s.Flags |= SignalStackFlagOnStack
}

// Contains checks if the stack pointer is within this stack.
func (s *SignalStack) Contains(sp usermem.Addr) bool {
	return usermem.Addr(s.Addr) < sp && sp <= usermem.Addr(s.Addr+s.Size)
}

// NativeSignalStack is a type that is equivalent to stack_t in the guest
// architecture.
type NativeSignalStack interface {
	marshal.Marshallable

	// SerializeFrom copies the data in the host SignalStack s into this
	// object.
	SerializeFrom(s *SignalStack)

	// DeserializeTo copies the data in this object into the host SignalStack
	// s.
	DeserializeTo(s *SignalStack)
}
