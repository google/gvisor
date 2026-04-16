// Copyright 2020 The gVisor Authors.
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

package runsc

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const filename = "state.json"

// State holds information needed between shim invocations.
type State struct {
	// Rootfs is the full path to the location rootfs was mounted.
	Rootfs string `json:"rootfs"`

	// Options is the configuration loaded from config.toml.
	Options Options `json:"options"`
}

// Load loads the state from the given path.
func (s *State) Load(path string) error {
	data, err := os.ReadFile(filepath.Join(path, filename))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, s)
}

// Save saves the state to the given path.
func (s *State) Save(path string) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(path, filename), data, 0644)
}
