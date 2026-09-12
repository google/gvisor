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

// Package hostos contains utility functions for getting information about the host OS.
//
// The actual host queries are OS-specific: KernelVersion and TotalSystemMemory
// are implemented in hostos_linux.go and stubbed out elsewhere.
package hostos

import (
	"fmt"

	"golang.org/x/mod/semver"
)

// Version represents a semantic version of the form "%d.%d[.%d]".
type Version struct {
	version string
}

// AtLeast returns whether vr is at least version major.minor.
func (vr Version) AtLeast(major, minor int) bool {
	return semver.Compare(vr.version, fmt.Sprintf("v%d.%d", major, minor)) >= 0
}

// LessThan returns whether vr is less than version major.minor.
func (vr Version) LessThan(major, minor int) bool {
	return !vr.AtLeast(major, minor)
}

// String implements fmt.Stringer.
func (vr Version) String() string {
	if vr.version == "" {
		return "unknown"
	}
	// Omit the "v" prefix required by semver.
	return vr.version[1:]
}
