// Copyright 2020 The gVisor Authors.
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

//go:build !kcov && !false
// +build !kcov,!false

// Package coverage provides stub functions.
// We need a separate internal and external version because the
// internal/external packages that are used to collect coverage data have
// different interfaces and are not interchangeable through a simple
// transformation.
//
// Some parts of this package (e.g., kcov) are only used with runsc externally,
// so the internal version is quite bare.
package coverage

import (
	"io"
)

// Available returns whether any coverage data is available.
func Available() bool {
	return false
}

// EnableReport sets up coverage reporting.
func EnableReport(w io.WriteCloser) {
}

// Report writes out a coverage report with all blocks that have been covered.
func Report() error {
	return nil
}

// KcovSupported returns whether the kcov interface should be made available (it
// is only available externally).
func KcovSupported() bool {
	return false
}

// InitCoverageData initializes global kcov-related data structures.
//
// Only used for open-source.
func InitCoverageData() {}

// ClearCoverageData clears existing coverage data.
//
// Only used for open-source.
func ClearCoverageData() {}

// ConsumeCoverageData builds the collection of covered PCs.
//
// Only used for open-source.
func ConsumeCoverageData(w io.Writer) int {
	return 0
}

// Symbolize writes out information about the block corresponding to pc.
//
// Only used for open-source.
func Symbolize(out io.Writer, pc uint64) error {
	return nil
}

// WriteAllBlocks writes out all PCs along with their corresponding position in the
// source code.
//
// Only used for open-source.
func WriteAllBlocks(out io.Writer) error {
	return nil
}
