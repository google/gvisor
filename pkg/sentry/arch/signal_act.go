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

package arch

// Special values for SignalAct.Handler.
const (
	// SignalActDefault is SIG_DFL and specifies that the default behavior for
	// a signal should be taken.
	SignalActDefault = 0

	// SignalActIgnore is SIG_IGN and specifies that a signal should be
	// ignored.
	SignalActIgnore = 1
)

// Available signal flags.
const (
	SignalFlagNoCldStop    = 0x00000001
	SignalFlagNoCldWait    = 0x00000002
	SignalFlagSigInfo      = 0x00000004
	SignalFlagRestorer     = 0x04000000
	SignalFlagOnStack      = 0x08000000
	SignalFlagRestart      = 0x10000000
	SignalFlagInterrupt    = 0x20000000
	SignalFlagNoDefer      = 0x40000000
	SignalFlagResetHandler = 0x80000000
)

// IsSigInfo returns true iff this handle expects siginfo.
func (s SignalAct) IsSigInfo() bool {
	return s.Flags&SignalFlagSigInfo != 0
}

// IsNoDefer returns true iff this SignalAct has the NoDefer flag set.
func (s SignalAct) IsNoDefer() bool {
	return s.Flags&SignalFlagNoDefer != 0
}

// IsRestart returns true iff this SignalAct has the Restart flag set.
func (s SignalAct) IsRestart() bool {
	return s.Flags&SignalFlagRestart != 0
}

// IsResetHandler returns true iff this SignalAct has the ResetHandler flag set.
func (s SignalAct) IsResetHandler() bool {
	return s.Flags&SignalFlagResetHandler != 0
}

// IsOnStack returns true iff this SignalAct has the OnStack flag set.
func (s SignalAct) IsOnStack() bool {
	return s.Flags&SignalFlagOnStack != 0
}

// HasRestorer returns true iff this SignalAct has the Restorer flag set.
func (s SignalAct) HasRestorer() bool {
	return s.Flags&SignalFlagRestorer != 0
}

// NativeSignalAct is a type that is equivalent to struct sigaction in the
// guest architecture.
type NativeSignalAct interface {
	// SerializeFrom copies the data in the host SignalAct s into this object.
	SerializeFrom(s *SignalAct)

	// DeserializeTo copies the data in this object into the host SignalAct s.
	DeserializeTo(s *SignalAct)
}
