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

package check

import (
	"errors"
	"fmt"
	"go/build"
	"io"
	"os"

	"gvisor.dev/gvisor/tools/nogo/flags"
)

// findStdPkg needs to find the bundled standard library packages.
var findStdPkg = func(path string) (io.ReadCloser, error) {
	if path == "C" {
		// Cgo builds cannot be analyzed. Skip.
		return nil, ErrSkip
	}

	// Attempt to use the root, if available.
	root, envErr := flags.Env("GOROOT")
	if envErr != nil {
		return nil, fmt.Errorf("unable to resolve GOROOT: %w", envErr)
	}

	// Attempt to resolve the library, and propagate this error.
	f, err := os.Open(fmt.Sprintf("%s/pkg/%s_%s/%s.a", root, flags.GOOS, flags.GOARCH, path))
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, ErrSkip
	}
	return f, err
}

// releaseTags returns the default release tags.
var releaseTags = func() ([]string, error) {
	return build.Default.ReleaseTags, nil
}
