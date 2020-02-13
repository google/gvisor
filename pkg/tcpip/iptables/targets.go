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

// This file contains various Targets.

package iptables

import (
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// AcceptTarget accepts packets.
type AcceptTarget struct{}

// Action implements Target.Action.
func (AcceptTarget) Action(packet tcpip.PacketBuffer) (RuleVerdict, string) {
	return RuleAccept, ""
}

// DropTarget drops packets.
type DropTarget struct{}

// Action implements Target.Action.
func (DropTarget) Action(packet tcpip.PacketBuffer) (RuleVerdict, string) {
	return RuleDrop, ""
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct{}

// Action implements Target.Action.
func (ErrorTarget) Action(packet tcpip.PacketBuffer) (RuleVerdict, string) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, ""
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	Name string
}

// Action implements Target.Action.
func (UserChainTarget) Action(tcpip.PacketBuffer) (RuleVerdict, string) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct{}

// Action implements Target.Action.
func (ReturnTarget) Action(tcpip.PacketBuffer) (RuleVerdict, string) {
	return RuleReturn, ""
}
