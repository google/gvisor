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

package control

import (
	"errors"
	"runtime"
	"runtime/pprof"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
)

var errNoOutput = errors.New("no output writer provided")

// ProfileOpts contains options for the StartCPUProfile/Goroutine RPC call.
type ProfileOpts struct {
	// File is the filesystem path for the profile.
	File string `json:"path"`

	// FilePayload is the destination for the profiling output.
	urpc.FilePayload
}

// Profile includes profile-related RPC stubs. It provides a way to
// control the built-in pprof facility in sentry via sentryctl.
//
// The following options to sentryctl are added:
//
// - collect CPU profile on-demand.
//   sentryctl -pid <pid> pprof-cpu-start
//   sentryctl -pid <pid> pprof-cpu-stop
//
// - dump out the stack trace of current go routines.
//   sentryctl -pid <pid> pprof-goroutine
type Profile struct {
	// mu protects the fields below.
	mu sync.Mutex

	// cpuFile is the current CPU profile output file.
	cpuFile *fd.FD
}

// StartCPUProfile is an RPC stub which starts recording the CPU profile in a
// file.
func (p *Profile) StartCPUProfile(o *ProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return errNoOutput
	}

	output, err := fd.NewFromFile(o.FilePayload.Files[0])
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Returns an error if profiling is already started.
	if err := pprof.StartCPUProfile(output); err != nil {
		output.Close()
		return err
	}

	p.cpuFile = output
	return nil
}

// StopCPUProfile is an RPC stub which stops the CPU profiling and flush out the
// profile data. It takes no argument.
func (p *Profile) StopCPUProfile(_, _ *struct{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cpuFile == nil {
		return errors.New("CPU profiling not started")
	}

	pprof.StopCPUProfile()
	p.cpuFile.Close()
	p.cpuFile = nil
	return nil
}

// HeapProfile generates a heap profile for the sentry.
func (p *Profile) HeapProfile(o *ProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return errNoOutput
	}
	output := o.FilePayload.Files[0]
	defer output.Close()
	runtime.GC() // Get up-to-date statistics.
	if err := pprof.WriteHeapProfile(output); err != nil {
		return err
	}
	return nil
}

// Goroutine is an RPC stub which dumps out the stack trace for all running
// goroutines.
func (p *Profile) Goroutine(o *ProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return errNoOutput
	}
	output := o.FilePayload.Files[0]
	defer output.Close()
	if err := pprof.Lookup("goroutine").WriteTo(output, 2); err != nil {
		return err
	}
	return nil
}
