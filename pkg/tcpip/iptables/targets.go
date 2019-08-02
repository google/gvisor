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

import "gvisor.dev/gvisor/pkg/tcpip/buffer"

// UnconditionalAcceptTarget accepts all packets.
type UnconditionalAcceptTarget struct{}

// Action implements Target.Action.
func (UnconditionalAcceptTarget) Action(packet buffer.VectorisedView) (Verdict, string) {
	return Accept, ""
}

// UnconditionalDropTarget denies all packets.
type UnconditionalDropTarget struct{}

// Action implements Target.Action.
func (UnconditionalDropTarget) Action(packet buffer.VectorisedView) (Verdict, string) {
	return Drop, ""
}
