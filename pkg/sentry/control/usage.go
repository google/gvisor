// Copyright 2021 The gVisor Authors.
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
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"gvisor.dev/gvisor/pkg/control/api"
	"gvisor.dev/gvisor/pkg/sentry/fsmetric"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Usage includes usage-related RPC stubs.
type Usage struct {
	Kernel *kernel.Kernel
}

// MemoryUsageOpts contains usage options.
type MemoryUsageOpts = api.MemoryUsageOpts

// MemoryUsage is a memory usage structure.
type MemoryUsage = api.MemoryUsage

// MemoryUsageFileOpts contains usage file options.
type MemoryUsageFileOpts = api.MemoryUsageFileOpts

// MemoryUsageFile contains the file handle to the usage file.
type MemoryUsageFile = api.MemoryUsageFile

// UsageFD returns the file that tracks the memory usage of the application.
func (u *Usage) UsageFD(opts *MemoryUsageFileOpts, out *MemoryUsageFile) error {
	// Only support version 1 for now.
	if opts.Version != 1 {
		return fmt.Errorf("unsupported version requested: %d", opts.Version)
	}

	mf := u.Kernel.MemoryFile()
	*out = MemoryUsageFile{
		FilePayload: urpc.FilePayload{
			Files: []*os.File{
				usage.MemoryAccounting.File,
				mf.File(),
			},
		},
	}

	return nil
}

// Collect returns memory used by the sandboxed application.
func (u *Usage) Collect(opts *MemoryUsageOpts, out *MemoryUsage) error {
	if opts.Full {
		// Ensure everything is up to date.
		if err := u.Kernel.MemoryFile().UpdateUsage(nil); err != nil {
			return err
		}

		// Copy out a snapshot.
		snapshot, total := usage.MemoryAccounting.Copy()
		*out = MemoryUsage{
			System:    snapshot.System,
			Anonymous: snapshot.Anonymous,
			PageCache: snapshot.PageCache,
			Mapped:    snapshot.Mapped,
			Tmpfs:     snapshot.Tmpfs,
			Ramdiskfs: snapshot.Ramdiskfs,
			Total:     total,
		}
	} else {
		// Get total usage from the MemoryFile implementation.
		total, err := u.Kernel.MemoryFile().TotalUsage()
		if err != nil {
			return err
		}

		// The memory accounting is guaranteed to be accurate only when
		// UpdateUsage is called. If UpdateUsage is not called, then only Mapped
		// will be up-to-date.
		snapshot, _ := usage.MemoryAccounting.Copy()
		*out = MemoryUsage{
			Unknown: total,
			Mapped:  snapshot.Mapped,
			Total:   total + snapshot.Mapped,
		}

	}

	return nil
}

// UsageReduceOpts contains options to Usage.Reduce().
type UsageReduceOpts struct {
	// If Wait is `true`, Reduce blocks until all activity initiated by
	// Usage.Reduce() has completed.
	// If Wait is `false`, Go garbage collection is still performed and may
	// still block for some time, unless `DoNotGC` is `true`.
	Wait bool `json:"wait"`

	// If DoNotGC is true, Reduce does not explicitly run Go garbage collection.
	// Garbage collection may block for an indeterminate amount of time.
	// Note that the runtime Go may still perform routine garbage collection at
	// any time during program execution, so a routine GC is still possible even
	// when this option set to `true`.
	DoNotGC bool `json:"do_not_gc"`
}

// UsageReduceOutput contains output from Usage.Reduce().
type UsageReduceOutput struct{}

// Reduce requests that the sentry attempt to reduce its memory usage.
func (u *Usage) Reduce(opts *UsageReduceOpts, out *UsageReduceOutput) error {
	mf := u.Kernel.MemoryFile()
	mf.StartEvictions()
	if opts.Wait {
		mf.WaitForEvictions()
	}
	if !opts.DoNotGC {
		runtime.GC()
	}
	return nil
}

// GetFileIoStats writes the read times in nanoseconds to out.
func (*Usage) GetFileIoStats(_ *struct{}, out *string) error {
	fileIoStats := struct {
		// The total amount of time spent reading. The map maps gopher prefixes
		// to the total time spent reading. Times not included in a known prefix
		// are placed in the "/" prefix.
		ReadWait map[string]uint64 `json:"ReadWait"`
		// The total amount of time spent reading. The map maps gopher prefixes
		// to the total time spent reading. Times not included in a known prefix
		// are placed in the "/" prefix.
		ReadWait9P map[string]uint64 `json:"ReadWait9P"`
	}{
		ReadWait:   map[string]uint64{"/": fsmetric.ReadWait.Value()},
		ReadWait9P: map[string]uint64{"/": fsmetric.GoferReadWait9P.Value()},
	}

	m, err := json.Marshal(fileIoStats)
	if err != nil {
		return err
	}
	*out = string(m)
	return nil
}
