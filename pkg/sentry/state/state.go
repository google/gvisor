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

// Package state provides high-level state wrappers.
package state

import (
	"errors"
	"fmt"
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/state/statefile"
)

var previousMetadata map[string]string

const (
	// GvisorCPUUsageKey is the metadata key to store and retrieve CPU time usage
	// across save restore.
	GvisorCPUUsageKey = "gvisor_cpu_usage"
	// GvisorWallTimeKey is the metadata key to store and retrieve wall time
	// across save restore.
	GvisorWallTimeKey = "gvisor_wall_time"
)

// SaveOpts contains save-related options.
type SaveOpts struct {
	// Destination is the save target.
	Destination io.Writer

	// PagesMetadata is the file into which MemoryFile metadata is stored if
	// PagesMetadata is non-nil. Otherwise this content is stored in Destination.
	PagesMetadata io.WriteCloser

	// PagesFile is the file in which all MemoryFile pages are stored if
	// PagesFile is non-nil. Otherwise this content is stored in Destination.
	PagesFile stateio.AsyncWriter

	// Key is used for state integrity check.
	Key []byte

	// Metadata is save metadata.
	Metadata map[string]string

	// AppMFExcludeCommittedZeroPages is the value of
	// pgalloc.SaveOpts.ExcludeCommittedZeroPages for the application memory
	// file.
	AppMFExcludeCommittedZeroPages bool

	// Resume indicates if the statefile is used for save-resume.
	Resume bool

	// Autosave indicates if the statefile is used for autosave.
	Autosave bool

	// StartTime stores the start time of the sandbox.
	StartTime time.Time
}

// Close releases resources owned by opts.
func (opts *SaveOpts) Close() error {
	var dstErr, pmErr, pfErr error
	if c, ok := opts.Destination.(io.Closer); ok {
		dstErr = c.Close()
	}
	if opts.PagesMetadata != nil {
		pmErr = opts.PagesMetadata.Close()
	}
	if opts.PagesFile != nil {
		pfErr = opts.PagesFile.Close()
	}
	return errors.Join(dstErr, pmErr, pfErr)
}

// Save saves the system state.
func (opts *SaveOpts) Save(ctx context.Context, k *kernel.Kernel, w *watchdog.Watchdog) error {
	t, err := CPUTime()
	if err != nil {
		log.Warningf("Error getting cpu time: %v", err)
	}
	log.Infof("Before save CPU usage: %s", t.String())

	// Get the current time before save to calculate wall time.
	var wt time.Duration
	curTime := time.Now()
	if opts.StartTime.IsZero() {
		log.Warningf("Cannot calculate wall time as start time is not available")
	} else {
		wt = curTime.Sub(opts.StartTime)
		log.Infof("Before save wall time: %s", wt.String())
	}

	log.Infof("Sandbox save started, pausing all tasks.")
	k.Pause()
	k.ReceiveTaskStates()
	defer func() {
		k.Unpause()
		log.Infof("Tasks resumed after save.")
	}()

	w.Stop()
	defer w.Start()

	// Supplement the metadata.
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]string)
	}
	if previousMetadata != nil {
		// Update CPU time and wall time based on the previous runs.
		p, err := time.ParseDuration(previousMetadata[GvisorCPUUsageKey])
		if err != nil {
			log.Warningf("Error parsing previous runs' cpu time: %v", err)
		}
		t += p

		w, err := time.ParseDuration(previousMetadata[GvisorWallTimeKey])
		if err != nil {
			log.Warningf("Error parsing previous runs' wall time: %v", err)
		}
		wt += w
	}
	opts.Metadata[GvisorCPUUsageKey] = t.String()
	if wt != 0 {
		opts.Metadata[GvisorWallTimeKey] = wt.String()
	}
	addSaveMetadata(opts.Metadata)

	// Open the statefile.
	wc, err := statefile.NewWriter(opts.Destination, opts.Key, opts.Metadata) // transfers ownership of opts.Destination to wc if err == nil
	if err != nil {
		err = fmt.Errorf("statefile.NewWriter failed: %w", err)
	} else {
		opts.Destination = nil
		// Save the kernel.
		err = k.SaveTo(ctx, wc, opts.PagesMetadata, opts.PagesFile, opts.AppMFExcludeCommittedZeroPages, opts.Resume) // transfers ownership of wc, opts.PagesMetadata, opts.PagesFile
		opts.PagesMetadata = nil
		opts.PagesFile = nil
	}

	t1, _ := CPUTime()
	log.Infof("Save CPU usage: %s", (t1 - t).String())
	if err == nil {
		log.Infof("Save succeeded: exiting...")
		k.SetSaveSuccess(opts.Autosave)
	} else {
		log.Warningf("Save failed: exiting... %v", err)
		k.SetSaveError(err)
	}
	if opts.Resume {
		k.BeforeResume(ctx)
	} else {
		// Kill the sandbox.
		k.Kill(linux.WaitStatusExit(0))
	}
	return err
}

// NewStatefileReader returns the statefile's metadata and a reader for it.
// The ownership of source is transferred to the returned reader.
func NewStatefileReader(source io.ReadCloser, key []byte) (io.ReadCloser, map[string]string, error) {
	r, m, err := statefile.NewReader(source, key)
	if err != nil {
		return nil, nil, fmt.Errorf("statefile.NewReader failed: %w", err)
	}
	previousMetadata = m
	return r, m, nil
}
