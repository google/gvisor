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

// Package flipcall implements a protocol providing Fast Local Interprocess
// Procedure Calls.
package flipcall

// ControlMode defines how control is exchanged across a connection.
type ControlMode uint8

const (
	// ControlModeInvalid is invalid, and exists so that ControlMode fields in
	// structs must be explicitly initialized.
	ControlModeInvalid ControlMode = iota

	// ControlModeFutex uses shared futex operations on packet control words.
	ControlModeFutex

	// controlModeCount is the number of ControlModes in this list.
	controlModeCount
)
