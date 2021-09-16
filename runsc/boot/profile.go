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

package boot

import (
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
)

// startProfiling initiates profiling as defined by the ProfileConfig, and
// returns a function that should be called to stop profiling.
func startProfiling(args Args) func() {
	var onStopProfiling []func()
	stopProfiling := func() {
		for _, f := range onStopProfiling {
			f()
		}
	}

	if args.ProfileBlockFD >= 0 {
		file := os.NewFile(uintptr(args.ProfileBlockFD), "profile-block")

		runtime.SetBlockProfileRate(control.DefaultBlockProfileRate)
		onStopProfiling = append(onStopProfiling, func() {
			if err := pprof.Lookup("block").WriteTo(file, 0); err != nil {
				log.Warningf("Error writing block profile: %v", err)
			}
			file.Close()
			runtime.SetBlockProfileRate(0)
		})
	}

	if args.ProfileCPUFD >= 0 {
		file := os.NewFile(uintptr(args.ProfileCPUFD), "profile-cpu")

		pprof.StartCPUProfile(file)
		onStopProfiling = append(onStopProfiling, func() {
			pprof.StopCPUProfile()
			file.Close()
		})
	}

	if args.ProfileHeapFD >= 0 {
		file := os.NewFile(uintptr(args.ProfileHeapFD), "profile-heap")

		onStopProfiling = append(onStopProfiling, func() {
			if err := pprof.Lookup("heap").WriteTo(file, 0); err != nil {
				log.Warningf("Error writing heap profile: %v", err)
			}
			file.Close()
		})
	}

	if args.ProfileMutexFD >= 0 {
		file := os.NewFile(uintptr(args.ProfileMutexFD), "profile-mutex")

		prev := runtime.SetMutexProfileFraction(control.DefaultMutexProfileRate)
		onStopProfiling = append(onStopProfiling, func() {
			if err := pprof.Lookup("mutex").WriteTo(file, 0); err != nil {
				log.Warningf("Error writing mutex profile: %v", err)
			}
			file.Close()
			runtime.SetMutexProfileFraction(prev)
		})
	}

	if args.TraceFD >= 0 {
		file := os.NewFile(uintptr(args.TraceFD), "trace")

		trace.Start(file)
		onStopProfiling = append(onStopProfiling, func() {
			trace.Stop()
			file.Close()
		})
	}

	return stopProfiling
}
