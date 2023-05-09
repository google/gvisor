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

//go:build (amd64 || 386) && go1.1
// +build amd64 386
// +build go1.1

package arch

import (
	"gvisor.dev/gvisor/pkg/sentry/arch/fpu"
)

// State contains the common architecture bits for X86 (the build tag of this
// file ensures it's only built on x86).
//
// +stateify savable
type State struct {
	// The system registers.
	Regs Registers

	// Our floating point state.
	fpState fpu.State `state:"wait"`
}

// afterLoad is invoked by stateify.
func (s *State) afterLoad() {
	s.afterLoadFPState()
}
