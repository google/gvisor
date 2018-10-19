// Copyright 2018 Google LLC
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

package control

import (
	"errors"

	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/state"
	"gvisor.googlesource.com/gvisor/pkg/sentry/watchdog"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
)

// ErrInvalidFiles is returned when the urpc call to Save does not include an
// appropriate file payload (e.g. there is no output file!).
var ErrInvalidFiles = errors.New("exactly one file must be provided")

// State includes state-related functions.
type State struct {
	Kernel   *kernel.Kernel
	Watchdog *watchdog.Watchdog
}

// SaveOpts contains options for the Save RPC call.
type SaveOpts struct {
	// Key is used for state integrity check.
	Key []byte `json:"key"`

	// Metadata is the set of metadata to prepend to the state file.
	Metadata map[string]string `json:"metadata"`

	// FilePayload contains the destination for the state.
	urpc.FilePayload
}

// Save saves the running system.
func (s *State) Save(o *SaveOpts, _ *struct{}) error {
	// Create an output stream.
	if len(o.FilePayload.Files) != 1 {
		return ErrInvalidFiles
	}
	defer o.FilePayload.Files[0].Close()

	// Save to the first provided stream.
	saveOpts := state.SaveOpts{
		Destination: o.FilePayload.Files[0],
		Key:         o.Key,
		Metadata:    o.Metadata,
		Callback: func(err error) {
			if err == nil {
				log.Infof("Save succeeded: exiting...")
			} else {
				log.Warningf("Save failed: exiting...")
				s.Kernel.SetExitError(err)
			}
			s.Kernel.Kill(kernel.ExitStatus{})
		},
	}
	return saveOpts.Save(s.Kernel, s.Watchdog)
}
