// Copyright 2022 The gVisor Authors.
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

package seccheck

import (
	"fmt"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
)

var sessionsMu = sync.Mutex{}
var sessions = make(map[string]*State)

type SessionConfig struct {
	Name   string        `json:"name,omitempty"`
	Points []PointConfig `json:"points,omitempty"`
	Sinks  []SinkConfig  `json:"sinks,omitempty"`
}

type PointConfig struct {
	Name           string   `json:"name,omitempty"`
	OptionalFields []string `json:"optional_fields,omitempty"`
	ContextFields  []string `json:"context_fields,omitempty"`
}

type SinkConfig struct {
	Name             string                 `json:"name,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
	IgnoreSetupError bool                   `json:"ignore_setup_error,omitempty"`
	FD               *fd.FD                 `json:"-"`
}

func Create(conf *SessionConfig) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if _, ok := sessions[conf.Name]; ok {
		return fmt.Errorf("session %q already exists", conf.Name)
	}
	if conf.Name != "Default" {
		return fmt.Errorf(`only a single "Default" session is supported`)
	}
	state := &Global

	var reqs []PointReq
	for _, ptConfig := range conf.Points {
		desc, err := findPointDesc(ptConfig.Name)
		if err != nil {
			return err
		}
		req := PointReq{Pt: desc.ID}

		mask, err := setFields(ptConfig.OptionalFields, desc.OptionalFields)
		if err != nil {
			return err
		}
		req.Fields.Local = mask

		mask, err = setFields(ptConfig.ContextFields, desc.ContextFields)
		if err != nil {
			return err
		}
		req.Fields.Context = mask

		reqs = append(reqs, req)
	}

	for _, sinkConfig := range conf.Sinks {
		sink, err := findSinkDesc(sinkConfig.Name)
		if err != nil {
			return err
		}
		checker, err := sink.New(sinkConfig.Config, sinkConfig.FD)
		if err != nil {
			return err
		}
		state.AppendChecker(checker, reqs)
	}

	sessions[conf.Name] = state
	return nil
}

func SetupSinks(sinks []SinkConfig) ([]*os.File, error) {
	var files []*os.File
	for _, sink := range sinks {
		sinkFile, err := setupSink(sink)
		if err != nil {
			if !sink.IgnoreSetupError {
				return nil, err
			}
			log.Warningf("Ignoring sink setup failure: %v", err)
			// Ensure sinkFile is nil and append it to the list to ensure the file
			// order is preserved.
			sinkFile = nil
		}
		files = append(files, sinkFile)
	}
	return files, nil
}

func setupSink(config SinkConfig) (*os.File, error) {
	sink, err := findSinkDesc(config.Name)
	if err != nil {
		return nil, err
	}
	if sink.Setup == nil {
		return nil, nil
	}
	return sink.Setup(config.Config)
}

func Delete(name string) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	session := sessions[name]
	if session == nil {
		return fmt.Errorf("session %q not found", name)
	}

	session.clearCheckers()
	delete(sessions, name)
	return nil
}

func List(out *[]SessionConfig) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	for name := range sessions {
		// Only report session name. Consider adding rest of the fields as needed.
		*out = append(*out, SessionConfig{Name: name})
	}
}

func findPointDesc(name string) (PointDesc, error) {
	if desc, ok := Points[name]; ok {
		return desc, nil
	}
	return PointDesc{}, fmt.Errorf("point %q not found", name)
}

func findField(name string, fields []FieldDesc) (FieldDesc, error) {
	for _, f := range fields {
		if f.Name == name {
			return f, nil
		}
	}
	return FieldDesc{}, fmt.Errorf("field %q not found", name)
}

func setFields(names []string, fields []FieldDesc) (FieldMask, error) {
	fm := FieldMask{}
	for _, name := range names {
		desc, err := findField(name, fields)
		if err != nil {
			return FieldMask{}, err
		}
		fm.Add(desc.ID)
	}
	return fm, nil
}

func findSinkDesc(name string) (SinkDesc, error) {
	if desc, ok := Sinks[name]; ok {
		return desc, nil
	}
	return SinkDesc{}, fmt.Errorf("sink %q not found", name)
}
