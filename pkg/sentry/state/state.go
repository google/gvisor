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
	"bufio"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sentry/watchdog"
	"gvisor.dev/gvisor/pkg/state/statefile"
)

var previousMetadata map[string]string

// ErrStateFile is returned when an error is encountered writing the statefile
// (which may occur during open or close calls in addition to write).
type ErrStateFile struct {
	Err error
}

// Error implements error.Error().
func (e ErrStateFile) Error() string {
	return fmt.Sprintf("statefile error: %v", e.Err)
}

// SaveOpts contains save-related options.
type SaveOpts struct {
	// Destination is the save target.
	Destination io.Writer

	// PagesMetadata is the file into which MemoryFile metadata is stored if
	// PagesMetadata is non-nil. Otherwise this content is stored in Destination.
	PagesMetadata *fd.FD

	// PagesFile is the file in which all MemoryFile pages are stored if
	// PagesFile is non-nil. Otherwise this content is stored in Destination.
	PagesFile *fd.FD

	// Key is used for state integrity check.
	Key []byte

	// Metadata is save metadata.
	Metadata map[string]string

	// MemoryFileSaveOpts is passed to calls to pgalloc.MemoryFile.SaveTo().
	MemoryFileSaveOpts pgalloc.SaveOpts

	// Resume indicates if the statefile is used for save-resume.
	Resume bool

	// Autosave indicates if the statefile is used for autosave.
	Autosave bool
}

// Save saves the system state.
func (opts SaveOpts) Save(ctx context.Context, k *kernel.Kernel, w *watchdog.Watchdog) error {
	t, _ := CPUTime()
	log.Infof("Before save CPU usage: %s", t.String())

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
	addSaveMetadata(opts.Metadata)

	// Open the statefile.
	wc, err := statefile.NewWriter(opts.Destination, opts.Key, opts.Metadata)
	if err != nil {
		err = ErrStateFile{err}
	} else {
		var pagesMetadata io.Writer
		if opts.PagesMetadata != nil {
			// //pkg/state/wire writes one byte at a time; buffer these writes
			// to avoid making one syscall per write. For the "main" state
			// file, this buffering is handled by statefile.NewWriter() =>
			// compressio.Writer or compressio.NewSimpleWriter().
			pagesMetadata = bufio.NewWriter(opts.PagesMetadata)
		}

		// Save the kernel.
		err = k.SaveTo(ctx, wc, pagesMetadata, opts.PagesFile, opts.MemoryFileSaveOpts)

		// ENOSPC is a state file error. This error can only come from
		// writing the state file, and not from fs.FileOperations.Fsync
		// because we wrap those in kernel.TaskSet.flushWritesToFiles.
		if linuxerr.Equals(linuxerr.ENOSPC, err) {
			err = ErrStateFile{err}
		}

		if closeErr := wc.Close(); err == nil && closeErr != nil {
			err = ErrStateFile{closeErr}
		}
		if pagesMetadata != nil {
			if flushErr := pagesMetadata.(*bufio.Writer).Flush(); err == nil && flushErr != nil {
				err = ErrStateFile{flushErr}
			}
		}
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

// LoadOpts contains load-related options.
type LoadOpts struct {
	// Source is the load source.
	Source io.Reader

	// PagesFileLoader is an optional PagesFileLoader.
	// If unset, it will be created from `Source`.
	PagesFileLoader kernel.PagesFileLoader

	// If Background is true, the sentry may read from PagesFile after Load has
	// returned.
	Background bool

	// Key is used for state integrity check.
	Key []byte
}

// Load loads the given kernel, setting the provided platform and stack.
//
// Load takes ownership of (and unsets) opts.PagesFile.
func (opts LoadOpts) Load(ctx context.Context, k *kernel.Kernel, timeReady chan struct{}, n inet.Stack, clocks time.Clocks, vfsOpts *vfs.CompleteRestoreOptions, saveRestoreNet bool) error {
	r, m, err := statefile.NewReader(opts.Source, opts.Key)
	if err != nil {
		return ErrStateFile{err}
	}
	pfl := opts.PagesFileLoader
	if pfl == nil {
		pfl = kernel.NewSingleStateFilePagesFileLoader(r)
	}
	previousMetadata = m
	return k.LoadFrom(ctx, r, pfl, opts.Background, timeReady, n, clocks, vfsOpts, saveRestoreNet)
}
