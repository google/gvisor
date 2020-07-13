// Copyright 2019 The gVisor Authors.
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

package nogo

import (
	"fmt"
	"io"
	"os"
)

var (
	// internalPrefix is the internal path prefix. Note that this is not
	// special, as paths should be passed relative to the repository root
	// and should not have any special prefix applied.
	internalPrefix = fmt.Sprintf("^")

	// externalPrefix is external workspace packages.
	externalPrefix = "^external/"
)

// findStdPkg needs to find the bundled standard library packages.
func findStdPkg(path, GOOS, GOARCH string) (io.ReadCloser, error) {
	if path == "C" {
		// Cgo builds cannot be analyzed. Skip.
		return nil, ErrSkip
	}
	return os.Open(fmt.Sprintf("external/go_sdk/pkg/%s_%s/%s.a", GOOS, GOARCH, path))
}
