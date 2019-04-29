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

package container

// Status enumerates container statuses. The statuses and their semantics are
// part of the runtime CLI spec.
type Status int

const (
	// Created indicates "the runtime has finished the create operation and
	// the container process has neither exited nor executed the
	// user-specified program".
	Created Status = iota

	// Creating indicates "the container is being created".
	Creating

	// Paused indicates that the process within the container has been
	// suspended.
	Paused

	// Running indicates "the container process has executed the
	// user-specified program but has not exited".
	Running

	// Stopped indicates "the container process has exited".
	Stopped
)

// String converts a Status to a string. These strings are part of the runtime
// CLI spec and should not be changed.
func (s Status) String() string {
	switch s {
	case Created:
		return "created"
	case Creating:
		return "creating"
	case Paused:
		return "paused"
	case Running:
		return "running"
	case Stopped:
		return "stopped"
	default:
		return "unknown"
	}

}
