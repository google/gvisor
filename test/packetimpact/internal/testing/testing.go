// Copyright 2021 The gVisor Authors.
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

// Package testing provides common testing functionalities.
package testing

import (
	"fmt"
	"os"
	"path/filepath"
)

// UndeclaredOutput creates a path under the undeclared outputs directory.
func UndeclaredOutput(name string) (string, error) {
	const testUndeclaredOutputsDir = "TEST_UNDECLARED_OUTPUTS_DIR"
	if dir, ok := os.LookupEnv(testUndeclaredOutputsDir); ok {
		return filepath.Join(dir, name), nil
	}
	return "", fmt.Errorf("no %s env var", testUndeclaredOutputsDir)
}
