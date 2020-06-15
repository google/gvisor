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

package control

import (
	"errors"
	"fmt"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/urpc"
)

// ErrInvalidFiles is returned when the urpc call to Save does not include an
// appropriate file payload (e.g. there is no output file!).
var ErrInvalidFiles = errors.New("exactly one file must be provided")

// State includes state-related functions.
type State struct {
	Kernel       *kernel.Kernel
	Watchdog     *watchdog.Watchdog
	methodFilter map[string]interface{}
}

// NewState returns a new State object.
func NewState(k *kernel.Kernel, w *watchdog.Watchdog, methodFilter map[string]interface{}) *State {
	return &State{Kernel: k, Watchdog: w, methodFilter: methodFilter}
}

func (s *State) checkMethod(method string) error {
	if s.methodFilter == nil {
		return nil
	}
	if _, ok := s.methodFilter[method]; !ok {
		return fmt.Errorf("command %v not allowed", method)
	}
	return nil
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
	if err := s.checkMethod("Save"); err != nil {
		return err
	}
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
				s.Kernel.SetSaveError(err)
			}
			s.Kernel.Kill(kernel.ExitStatus{})
		},
	}
	return saveOpts.Save(s.Kernel, s.Watchdog)
}
