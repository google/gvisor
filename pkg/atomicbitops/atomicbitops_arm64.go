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

// Package atomicbitops provides extensions to the sync/atomic package.
//
// All read-modify-write operations implemented by this package have
// acquire-release memory ordering (like sync/atomic).
package atomicbitops

import "gvisor.dev/gvisor/pkg/cpuid"

const (
	Arm64FeatureAtomics = 8
)

var arm64HasATOMICS = cpuid.HostFeatureSet().HasFeature(Arm64FeatureAtomics)
