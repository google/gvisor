// Copyright 2025 The gVisor Authors.
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

// Package gvisordetect implements a library that callers may use to detect
// whether they are running on a gVisor kernel, assuming it is configured
// to expose the gVisor marker file.
package gvisordetect

import (
	"errors"
	"fmt"
	"os"
)

// RunningInGVisor checks if the caller is running against a gVisor kernel.
// This is only accurate if the gVisor kernel is configured to expose
// its marker file.
func RunningInGVisor() (bool, error) {
	const markerFilePath = "/proc/gvisor/kernel_is_gvisor"

	_, err := os.Stat(markerFilePath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("cannot detect whether running in gVisor: %w", err)
}
