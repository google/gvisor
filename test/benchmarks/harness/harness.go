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

// Package harness holds utility code for running benchmarks on Docker.
package harness

import (
	"flag"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// Harness is a handle for managing state in benchmark runs.
type Harness struct {
}

// Init performs any harness initilialization before runs.
func (h *Harness) Init() error {
	flag.Parse()
	dockerutil.EnsureSupportedDockerVersion()
	return nil
}

// GetMachine returns this run's implementation of machine.
func (h *Harness) GetMachine() (Machine, error) {
	return &localMachine{}, nil
}
