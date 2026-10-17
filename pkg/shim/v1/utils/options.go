// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// runtimeOptionsFilename is the file in the bundle that holds the runtime
// options containerd hands the shim on stdin at `shim start`.
const runtimeOptionsFilename = "runtime-options.pb"

// maxRuntimeOptionsSize bounds how much is read from stdin.
const maxRuntimeOptionsSize = 1 << 20

// DrainRuntimeOptions reads the runtime options containerd wrote to r, up to
// maxRuntimeOptionsSize bytes. It returns nil if containerd sent nothing.
func DrainRuntimeOptions(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRuntimeOptionsSize))
	if err != nil {
		return nil, fmt.Errorf("read runtime options: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}

// SaveRuntimeOptions stores data in the bundle for ReadRuntimeOptions.
func SaveRuntimeOptions(bundle string, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return os.WriteFile(filepath.Join(bundle, runtimeOptionsFilename), data, 0600)
}

// ReadRuntimeOptions returns the marshalled options saved by
// SaveRuntimeOptions, or nil if there are none.
func ReadRuntimeOptions(bundle string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(bundle, runtimeOptionsFilename))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read runtime options: %w", err)
	}
	return data, nil
}
