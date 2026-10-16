// Copyright 2018 The gVisor Authors.
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

package sentryapi

import (
	"encoding/json"
	"io"
	"os"

	"gvisor.dev/gvisor/pkg/sentry/seccheck"

	// Register supported of sinks.
	_ "gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/null"
	_ "gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/remote"
)

// InitConfig represents the configuration to apply during pod creation. For
// now, it supports setting up a seccheck session.
type InitConfig struct {
	TraceSession seccheck.SessionConfig `json:"trace_session"`
}

// LoadInitConfig loads an InitConfig struct from a json formatted file.
func LoadInitConfig(path string) (*InitConfig, error) {
	config, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	return ReadInitConfig(config)
}

func ReadInitConfig(reader io.Reader) (*InitConfig, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	init := &InitConfig{}
	if err := decoder.Decode(init); err != nil {
		return nil, err
	}
	return init, nil
}

// Setup performs the actions defined in the InitConfig, e.g. setup seccheck
// session.
func (c *InitConfig) Setup() ([]*os.File, error) {
	return seccheck.SetupSinks(c.TraceSession.Sinks)
}
