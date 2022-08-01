// Copyright 2022 The gVisor Authors.
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

//go:build arm64
// +build arm64

package atomicbitops

import (
	"runtime"

	"golang.org/x/sys/cpu"
	"gvisor.dev/gvisor/pkg/cpuid"
)

var arm64HasATOMICS bool

func init() {
	// The gvisor cpuid package only works on Linux.
	// For all other operating systems, use Go's x/sys/cpu package
	// to get the one bit we care about here.
	//
	// See https://github.com/google/gvisor/issues/7849.
	if runtime.GOOS == "linux" {
		arm64HasATOMICS = cpuid.HostFeatureSet().HasFeature(cpuid.ARM64FeatureATOMICS)
	} else {
		arm64HasATOMICS = cpu.ARM64.HasATOMICS
	}
}
