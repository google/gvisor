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
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"time"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Profile includes profile-related RPC stubs. It provides a way to
// control the built-in runtime profiling facilities.
//
// The profile object must be instantied via NewProfile.
type Profile struct {
	// kernel is the kernel under profile. It's immutable.
	kernel *kernel.Kernel

	// cpuMu protects CPU profiling.
	cpuMu sync.Mutex

	// blockMu protects block profiling.
	blockMu sync.Mutex

	// mutexMu protects mutex profiling.
	mutexMu sync.Mutex

	// traceMu protects trace profiling.
	traceMu sync.Mutex

	// done is closed when profiling is done.
	done chan struct{}
}

// NewProfile returns a new Profile object.
func NewProfile(k *kernel.Kernel) *Profile {
	return &Profile{
		kernel: k,
		done:   make(chan struct{}),
	}
}

// Stop implements urpc.Stopper.Stop.
func (p *Profile) Stop() {
	close(p.done)
}

// CPUProfileOpts contains options specifically for CPU profiles.
type CPUProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`
}

// CPU is an RPC stub which collects a CPU profile.
func (p *Profile) CPU(o *CPUProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return nil // Allowed.
	}

	output := o.FilePayload.Files[0]
	defer output.Close()

	p.cpuMu.Lock()
	defer p.cpuMu.Unlock()

	// Returns an error if profiling is already started.
	if err := pprof.StartCPUProfile(output); err != nil {
		return err
	}
	defer pprof.StopCPUProfile()

	// Collect the profile.
	select {
	case <-time.After(o.Duration):
	case <-p.done:
	}

	return nil
}

// HeapProfileOpts contains options specifically for heap profiles.
type HeapProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Delay is the sleep time, similar to Duration. This may
	// not affect the data collected however, as the heap will
	// continue only the memory associated with the last alloc.
	Delay time.Duration `json:"delay"`
}

// Heap generates a heap profile.
func (p *Profile) Heap(o *HeapProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return nil // Allowed.
	}

	output := o.FilePayload.Files[0]
	defer output.Close()

	// Wait for the given delay.
	select {
	case <-time.After(o.Delay):
	case <-p.done:
	}

	// Get up-to-date statistics.
	runtime.GC()

	// Write the given profile.
	return pprof.WriteHeapProfile(output)
}

// GoroutineProfileOpts contains options specifically for goroutine profiles.
type GoroutineProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload
}

// Goroutine dumps out the stack trace for all running goroutines.
func (p *Profile) Goroutine(o *GoroutineProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return nil // Allowed.
	}

	output := o.FilePayload.Files[0]
	defer output.Close()

	return pprof.Lookup("goroutine").WriteTo(output, 2)
}

// BlockProfileOpts contains options specifically for block profiles.
type BlockProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`

	// Rate is the block profile rate.
	Rate int `json:"rate"`
}

// Block dumps a blocking profile.
func (p *Profile) Block(o *BlockProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return nil // Allowed.
	}

	output := o.FilePayload.Files[0]
	defer output.Close()

	p.blockMu.Lock()
	defer p.blockMu.Unlock()

	// Always set the rate. We then wait to collect a profile at this rate,
	// and disable when we're done. Note that the default here is 10%, which
	// will record a stacktrace 10% of the time when blocking occurs. Since
	// these events should not be super frequent, we expect this to achieve
	// a reasonable balance between collecting the data we need and imposing
	// a high performance cost (e.g. skewing even the CPU profile).
	rate := 10
	if o.Rate != 0 {
		rate = o.Rate
	}
	runtime.SetBlockProfileRate(rate)
	defer runtime.SetBlockProfileRate(0)

	// Collect the profile.
	select {
	case <-time.After(o.Duration):
	case <-p.done:
	}

	return pprof.Lookup("block").WriteTo(output, 0)
}

// MutexProfileOpts contains options specifically for mutex profiles.
type MutexProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`

	// Fraction is the mutex profile fraction.
	Fraction int `json:"fraction"`
}

// Mutex dumps a mutex profile.
func (p *Profile) Mutex(o *MutexProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return nil // Allowed.
	}

	output := o.FilePayload.Files[0]
	defer output.Close()

	p.mutexMu.Lock()
	defer p.mutexMu.Unlock()

	// Always set the fraction. Like the block rate above, we use
	// a default rate of 10% for the same reasons.
	fraction := 10
	if o.Fraction != 0 {
		fraction = o.Fraction
	}
	runtime.SetMutexProfileFraction(fraction)
	defer runtime.SetMutexProfileFraction(0)

	// Collect the profile.
	select {
	case <-time.After(o.Duration):
	case <-p.done:
	}

	return pprof.Lookup("mutex").WriteTo(output, 0)
}

// TraceProfileOpts contains options specifically for traces.
type TraceProfileOpts struct {
	// FilePayload is the destination for the profiling output.
	urpc.FilePayload

	// Duration is the duration of the profile.
	Duration time.Duration `json:"duration"`
}

// Trace is an RPC stub which starts collection of an execution trace.
func (p *Profile) Trace(o *TraceProfileOpts, _ *struct{}) error {
	if len(o.FilePayload.Files) < 1 {
		return nil // Allowed.
	}

	output, err := fd.NewFromFile(o.FilePayload.Files[0])
	if err != nil {
		return err
	}
	defer output.Close()

	p.traceMu.Lock()
	defer p.traceMu.Unlock()

	// Returns an error if profiling is already started.
	if err := trace.Start(output); err != nil {
		output.Close()
		return err
	}
	defer trace.Stop()

	// Ensure all trace contexts are registered.
	p.kernel.RebuildTraceContexts()

	// Wait for the trace.
	select {
	case <-time.After(o.Duration):
	case <-p.done:
	}

	// Similarly to the case above, if tasks have not ended traces, we will
	// lose information. Thus we need to rebuild the tasks in order to have
	// complete information. This will not lose information if multiple
	// traces are overlapping.
	p.kernel.RebuildTraceContexts()

	return nil
}
