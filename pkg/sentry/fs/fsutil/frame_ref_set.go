// Copyright 2018 Google LLC
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

package fsutil

import (
	"math"

	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
)

type frameRefSetFunctions struct{}

// MinKey implements segment.Functions.MinKey.
func (frameRefSetFunctions) MinKey() uint64 {
	return 0
}

// MaxKey implements segment.Functions.MaxKey.
func (frameRefSetFunctions) MaxKey() uint64 {
	return math.MaxUint64
}

// ClearValue implements segment.Functions.ClearValue.
func (frameRefSetFunctions) ClearValue(val *uint64) {
}

// Merge implements segment.Functions.Merge.
func (frameRefSetFunctions) Merge(_ platform.FileRange, val1 uint64, _ platform.FileRange, val2 uint64) (uint64, bool) {
	if val1 != val2 {
		return 0, false
	}
	return val1, true
}

// Split implements segment.Functions.Split.
func (frameRefSetFunctions) Split(_ platform.FileRange, val uint64, _ uint64) (uint64, uint64) {
	return val, val
}
