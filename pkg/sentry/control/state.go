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
	"time"

	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/urpc"
)

const (
	// SaveRestoreBinTimeoutKey is the key used to save the timeout for the
	// save/restore binary in the metadata during save/restore.
	SaveRestoreBinTimeoutKey = "save-restore-bin-timeout"

	// SaveRestoreBinPathKey is the key used to save the path to the save/restore
	// binary in the metadata during save/restore.
	SaveRestoreBinPathKey = "save-restore-bin-path"

	defaultSaveRestoreBinTimeout = 10 * time.Second
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

	// MemoryFileSaveOpts is passed to calls to pgalloc.MemoryFile.SaveTo().
	MemoryFileSaveOpts pgalloc.SaveOpts

	// HavePagesFile indicates whether the pages file and its corresponding
	// metadata file is provided.
	HavePagesFile bool `json:"have_pages_file"`

	// FilePayload contains the following:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	urpc.FilePayload

	// Resume indicates if the sandbox process should continue running
	// after checkpointing.
	Resume bool
}

// Save saves the running system.
func (s *State) Save(o *SaveOpts, _ *struct{}) error {
	wantFiles := 1
	if o.HavePagesFile {
		wantFiles += 2
	}
	if gotFiles := len(o.FilePayload.Files); gotFiles != wantFiles {
		return fmt.Errorf("got %d files, wanted %d", gotFiles, wantFiles)
	}

	// Save to the first provided stream.
	stateFile, err := o.ReleaseFD(0)
	if err != nil {
		return err
	}
	defer stateFile.Close()
	saveOpts := state.SaveOpts{
		Destination:        stateFile,
		Key:                o.Key,
		Metadata:           o.Metadata,
		MemoryFileSaveOpts: o.MemoryFileSaveOpts,
		Resume:             o.Resume,
	}
	if o.HavePagesFile {
		saveOpts.PagesMetadata, err = o.ReleaseFD(1)
		if err != nil {
			return err
		}
		defer saveOpts.PagesMetadata.Close()

		saveOpts.PagesFile, err = o.ReleaseFD(2)
		if err != nil {
			return err
		}
		defer saveOpts.PagesFile.Close()
	}
	if saveRestoreBinPath, ok := o.Metadata[SaveRestoreBinPathKey]; ok {
		saveRestoreBinTimeout := defaultSaveRestoreBinTimeout
		if saveRestoreBinTimeoutString, ok := o.Metadata[SaveRestoreBinTimeoutKey]; ok {
			var err error
			saveRestoreBinTimeout, err = time.ParseDuration(saveRestoreBinTimeoutString)
			if err != nil {
				return fmt.Errorf("failed to parse save/restore bin timeout: %w", err)
			}
		}
		s.Kernel.SaveRestoreBinPath = saveRestoreBinPath
		s.Kernel.SaveRestoreBinTimeout = saveRestoreBinTimeout
		if _, err := s.Kernel.ExecSaveRestoreBin(kernel.SaveRestoreBinSave); err != nil {
			return fmt.Errorf("failed to exec save/restore binary: %w", err)
		}
	}
	return saveOpts.Save(s.Kernel.SupervisorContext(), s.Kernel, s.Watchdog)
}
