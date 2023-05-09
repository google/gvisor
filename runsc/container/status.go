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

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Status is a local type alias.
type Status = specs.ContainerState

const (
	// Created indicates "the runtime has finished the create operation and
	// the container process has neither exited nor executed the
	// user-specified program"
	Created = specs.StateCreated

	// Creating indicates "the container is being created".
	Creating = specs.StateCreating

	// Running indicates "the container process has executed the
	// user-specified program but has not exited".
	Running = specs.StateRunning

	// Stopped indicates "the container process has exited".
	Stopped = specs.StateStopped

	// Paused indicates that the process within the container has been
	// suspended. This is a local status, not part of the spec.
	Paused = Status("paused")
)
