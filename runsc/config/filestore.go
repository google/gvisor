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

// Package config provides basic infrastructure to set configuration settings
// for runsc. The configuration is set by flags to the command line. They can
// also propagate to a different process using the same flags.
package config

import "fmt"

// FilestoreReflinkMode controls permission to clone host filestore files.
type FilestoreReflinkMode int

// Filestore reflink modes.
const (
	FilestoreReflinkDisabled FilestoreReflinkMode = iota
	FilestoreReflinkEnabled
)

// FilestoreAdoptMode selects how restore obtains writable filestore files.
type FilestoreAdoptMode int

// Filestore adoption modes.
const (
	FilestoreAdoptClone FilestoreAdoptMode = iota
	FilestoreAdoptConsume
)

// Set implements flag.Value.
func (m *FilestoreReflinkMode) Set(value string) error {
	switch value {
	case "disabled":
		*m = FilestoreReflinkDisabled
	case "enabled":
		*m = FilestoreReflinkEnabled
	default:
		return fmt.Errorf("invalid filestore mode %q", value)
	}
	return nil
}

// String implements flag.Value.
func (m FilestoreReflinkMode) String() string {
	switch m {
	case FilestoreReflinkDisabled:
		return "disabled"
	case FilestoreReflinkEnabled:
		return "enabled"
	default:
		return fmt.Sprintf("invalid(%d)", m)
	}
}

// Get implements flag.Getter.
func (m *FilestoreReflinkMode) Get() any { return *m }

// Ptr returns a pointer to m.
func (m FilestoreReflinkMode) Ptr() *FilestoreReflinkMode { return &m }

// Set implements flag.Value.
func (m *FilestoreAdoptMode) Set(value string) error {
	switch value {
	case "clone":
		*m = FilestoreAdoptClone
	case "consume":
		*m = FilestoreAdoptConsume
	default:
		return fmt.Errorf("invalid filestore mode %q", value)
	}
	return nil
}

// String implements flag.Value.
func (m FilestoreAdoptMode) String() string {
	switch m {
	case FilestoreAdoptClone:
		return "clone"
	case FilestoreAdoptConsume:
		return "consume"
	default:
		return fmt.Sprintf("invalid(%d)", m)
	}
}

// Get implements flag.Getter.
func (m *FilestoreAdoptMode) Get() any { return *m }

// Ptr returns a pointer to m.
func (m FilestoreAdoptMode) Ptr() *FilestoreAdoptMode { return &m }
