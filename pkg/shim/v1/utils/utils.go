// Copyright 2018 The gVisor Authors.
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

// Package utils contains utility functions.
package utils

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ReadSpec reads OCI spec from the bundle directory.
func ReadSpec(bundle string) (*specs.Spec, error) {
	f, err := os.Open(filepath.Join(bundle, "config.json"))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var spec specs.Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// IsSandbox checks whether a container is a sandbox container.
func IsSandbox(spec *specs.Spec) bool {
	t, ok := spec.Annotations[containerTypeAnnotation]
	return !ok || t == containerTypeSandbox
}

// UserLogPath gets user log path from OCI annotation.
func UserLogPath(spec *specs.Spec) string {
	sandboxLogDir := spec.Annotations[sandboxLogDirAnnotation]
	if sandboxLogDir == "" {
		return ""
	}
	return filepath.Join(sandboxLogDir, "gvisor.log")
}
