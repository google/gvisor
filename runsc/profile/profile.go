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

// Package profile contains profiling utils.
package profile

import (
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/flag"
)

// Kind is the kind of profiling to perform.
type Kind int

const (
	// Block profile.
	Block Kind = iota
	// CPU profile.
	CPU
	// Heap profile.
	Heap
	// Mutex profile.
	Mutex
	// Trace profile.
	Trace
)

// FDArgs are the arguments that describe which profiles to enable and which
// FDs to write them to. Profiling of a given type will only be enabled if the
// corresponding FD is >=0.
type FDArgs struct {
	// BlockFD is the file descriptor to write a block profile to.
	// Valid if >=0.
	BlockFD int
	// CPUFD is the file descriptor to write a CPU profile to.
	// Valid if >=0.
	CPUFD int
	// HeapFD is the file descriptor to write a heap profile to.
	// Valid if >=0.
	HeapFD int
	// MutexFD is the file descriptor to write a mutex profile to.
	// Valid if >=0.
	MutexFD int
	// TraceFD is the file descriptor to write a Go execution trace to.
	// Valid if >=0.
	TraceFD int
}

// SetFromFlags sets the FDArgs from the given flags. The default value for
// each FD is -1.
func (fds *FDArgs) SetFromFlags(f *flag.FlagSet) {
	f.IntVar(&fds.BlockFD, "profile-block-fd", -1, "file descriptor to write block profile to. -1 disables profiling.")
	f.IntVar(&fds.CPUFD, "profile-cpu-fd", -1, "file descriptor to write CPU profile to. -1 disables profiling.")
	f.IntVar(&fds.HeapFD, "profile-heap-fd", -1, "file descriptor to write heap profile to. -1 disables profiling.")
	f.IntVar(&fds.MutexFD, "profile-mutex-fd", -1, "file descriptor to write mutex profile to. -1 disables profiling.")
	f.IntVar(&fds.TraceFD, "trace-fd", -1, "file descriptor to write Go execution trace to. -1 disables tracing.")
}

// Opts is a map of profile Kind to FD.
type Opts map[Kind]uintptr

// ToOpts turns FDArgs into an Opts struct which can be passed to Start.
func (fds *FDArgs) ToOpts() Opts {
	o := Opts{}
	if fds.BlockFD >= 0 {
		o[Block] = uintptr(fds.BlockFD)
	}
	if fds.CPUFD >= 0 {
		o[CPU] = uintptr(fds.CPUFD)
	}
	if fds.HeapFD >= 0 {
		o[Heap] = uintptr(fds.HeapFD)
	}
	if fds.MutexFD >= 0 {
		o[Mutex] = uintptr(fds.MutexFD)
	}
	if fds.TraceFD >= 0 {
		o[Trace] = uintptr(fds.TraceFD)
	}
	return o
}

// Start starts profiling for the given Kinds in opts, and writes the profile
// data to the corresponding FDs in opts. It returns a function which will stop
// profiling.
func Start(opts Opts) func() {
	var onStopProfiling []func()
	stopProfiling := func() {
		for _, f := range onStopProfiling {
			f()
		}
	}

	if fd, ok := opts[Block]; ok {
		log.Infof("Block profiling enabled")
		file := os.NewFile(fd, "profile-block")

		runtime.SetBlockProfileRate(control.DefaultBlockProfileRate)
		onStopProfiling = append(onStopProfiling, func() {
			if err := pprof.Lookup("block").WriteTo(file, 0); err != nil {
				log.Warningf("Error writing block profile: %v", err)
			}
			file.Close()
			runtime.SetBlockProfileRate(0)
			log.Infof("Block profiling stopped")
		})
	}

	if fd, ok := opts[CPU]; ok {
		log.Infof("CPU profiling enabled")
		file := os.NewFile(fd, "profile-cpu")

		pprof.StartCPUProfile(file)
		onStopProfiling = append(onStopProfiling, func() {
			pprof.StopCPUProfile()
			file.Close()
			log.Infof("CPU profiling stopped")
		})
	}

	if fd, ok := opts[Heap]; ok {
		log.Infof("Heap profiling enabled")
		file := os.NewFile(fd, "profile-heap")

		onStopProfiling = append(onStopProfiling, func() {
			if err := pprof.Lookup("heap").WriteTo(file, 0); err != nil {
				log.Warningf("Error writing heap profile: %v", err)
			}
			file.Close()
			log.Infof("Heap profiling stopped")
		})
	}

	if fd, ok := opts[Mutex]; ok {
		log.Infof("Mutex profiling enabled")
		file := os.NewFile(fd, "profile-mutex")

		prev := runtime.SetMutexProfileFraction(control.DefaultMutexProfileRate)
		onStopProfiling = append(onStopProfiling, func() {
			if err := pprof.Lookup("mutex").WriteTo(file, 0); err != nil {
				log.Warningf("Error writing mutex profile: %v", err)
			}
			file.Close()
			runtime.SetMutexProfileFraction(prev)
			log.Infof("Mutex profiling stopped")
		})
	}

	if fd, ok := opts[Trace]; ok {
		log.Infof("Tracing enabled")
		file := os.NewFile(fd, "trace")

		trace.Start(file)
		onStopProfiling = append(onStopProfiling, func() {
			trace.Stop()
			file.Close()
			log.Infof("Tracing stopped")
		})
	}

	return stopProfiling
}
