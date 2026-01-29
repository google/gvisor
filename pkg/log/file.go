// Copyright 2026 The gVisor Authors.
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

package log

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileOpts contains options for creating a log file.
type FileOpts interface {
	// Build constructs the log file path based on the given pattern.
	Build(logPattern string) string
}

// OpenFile opens a log file using the specified flags. It uses `opts` to
// construct the log file path based on the given `logPattern`.
func OpenFile(logPattern string, flags int, opts FileOpts) (*os.File, error) {
	if len(logPattern) == 0 {
		return nil, nil
	}

	// Replace variables in the log pattern.
	logPath := opts.Build(logPattern)

	// Create parent directory if it doesn't exist.
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0775); err != nil {
		return nil, fmt.Errorf("error creating dir %q: %v", dir, err)
	}

	// Open file with the specified flags.
	f, err := os.OpenFile(logPath, flags, 0664)
	if err != nil {
		return nil, fmt.Errorf("error opening file %q: %v", logPath, err)
	}
	return f, nil
}
