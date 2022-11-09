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

// DefaultSessionName is the name of the only session that can exist in the
// system for now. When multiple sessions are supported, this can be removed.
const DefaultSessionName = "Default"

var (
	sessionsMu = sync.Mutex{}
	sessions   = make(map[string]*State)
)

// SessionConfig describes a new session configuration. A session consists of a
// set of points to be enabled and sinks where the points are sent to.
type SessionConfig struct {
	// Name is the unique session name.
	Name string `json:"name,omitempty"`
	// Points is the set of points to enable in this session.
	Points []PointConfig `json:"points,omitempty"`
	// IgnoreMissing skips point and optional/context fields not found. This can
	// be used to apply a single configuration file with newer points/fields with
	// older versions which do not have them yet. Note that it may hide typos in
	// the configuration.
	//
	// This field does NOT apply to sinks.
	IgnoreMissing bool `json:"ignore_missing,omitempty"`
	// Sinks are the sinks that will process the points enabled above.
	Sinks []SinkConfig `json:"sinks,omitempty"`
}

// PointConfig describes a point to be enabled in a given session.
type PointConfig struct {
	// Name is the point to be enabled. The point must exist in the system.
	Name string `json:"name,omitempty"`
	// OptionalFields is the list of optional fields to collect from the point.
	OptionalFields []string `json:"optional_fields,omitempty"`
	// ContextFields is the list of context fields to collect.
	ContextFields []string `json:"context_fields,omitempty"`
}

// SinkConfig describes the sink that will process the points in a given
// session.
type SinkConfig struct {
	// Name is the sink to be created. The sink must exist in the system.
	Name string `json:"name,omitempty"`
	// Config is a opaque json object that is passed to the sink.
	Config map[string]any `json:"config,omitempty"`
	// IgnoreSetupError makes errors during sink setup to be ignored. Otherwise,
	// failures will prevent the container from starting.
	IgnoreSetupError bool `json:"ignore_setup_error,omitempty"`
	// Status is the runtime status for the sink.
	Status SinkStatus `json:"status,omitempty"`
	// FD is the endpoint returned from Setup. It may be nil.
	FD *fd.FD `json:"-"`
}

// Create reads the session configuration and applies it to the system.
func Create(conf *SessionConfig, force bool) error {
	log.Debugf("Creating seccheck: %+v", conf)
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	if _, ok := sessions[conf.Name]; ok {
		if !force {
			return fmt.Errorf("session %q already exists", conf.Name)
		}
		if err := deleteLocked(conf.Name); err != nil {
			return err
		}
		log.Infof("Trace session %q was deleted to be replaced", conf.Name)
	}
	if conf.Name != DefaultSessionName {
		return fmt.Errorf(`only a single "Default" session is supported`)
	}
	state := &Global

	var reqs []PointReq
	for _, ptConfig := range conf.Points {
		desc, err := findPointDesc(ptConfig.Name)
		if err != nil {
			if conf.IgnoreMissing {
				log.Warningf("Skipping point %q: %v", ptConfig.Name, err)
				continue
			}
			return err
		}
		req := PointReq{Pt: desc.ID}

		mask, err := setFields(ptConfig.OptionalFields, desc.OptionalFields, conf.IgnoreMissing)
		if err != nil {
			return fmt.Errorf("configuring point %q: %w", ptConfig.Name, err)
		}
		req.Fields.Local = mask

		mask, err = setFields(ptConfig.ContextFields, desc.ContextFields, conf.IgnoreMissing)
		if err != nil {
			return fmt.Errorf("configuring point %q: %w", ptConfig.Name, err)
		}
		req.Fields.Context = mask

		reqs = append(reqs, req)
	}

	for _, sinkConfig := range conf.Sinks {
		desc, err := findSinkDesc(sinkConfig.Name)
		if err != nil {
			return err
		}
		sink, err := desc.New(sinkConfig.Config, sinkConfig.FD)
		if err != nil {
			return fmt.Errorf("creating event sink: %w", err)
		}
		state.AppendSink(sink, reqs)
	}

	sessions[conf.Name] = state
	return nil
}

// SetupSinks runs the setup step of all sinks in the configuration.
func SetupSinks(sinks []SinkConfig) ([]*os.File, error) {
	var files []*os.File
	for _, sink := range sinks {
		sinkFile, err := setupSink(sink)
		if err != nil {
			if !sink.IgnoreSetupError {
				return nil, err
			}
			log.Warningf("Ignoring sink setup failure: %v", err)
			// Set sinkFile is nil and append it to the list to ensure the file
			// order is preserved.
			sinkFile = nil
		}
		files = append(files, sinkFile)
	}
	return files, nil
}

// setupSink runs the setup step for a given sink.
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

// Delete deletes an existing session.
func Delete(name string) error {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	return deleteLocked(name)
}

// +checklocks:sessionsMu
func deleteLocked(name string) error {
	session := sessions[name]
	if session == nil {
		return fmt.Errorf("session %q not found", name)
	}

	session.clearSink()
	delete(sessions, name)
	return nil
}

// List lists all existing sessions.
func List(out *[]SessionConfig) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()

	for name, state := range sessions {
		// Only report session name. Consider adding rest of the fields as needed.
		session := SessionConfig{Name: name}
		for _, sink := range state.getSinks() {
			session.Sinks = append(session.Sinks, SinkConfig{
				Name:   sink.Name(),
				Status: sink.Status(),
			})
		}
		*out = append(*out, session)
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

func setFields(names []string, fields []FieldDesc, ignoreMissing bool) (FieldMask, error) {
	fm := FieldMask{}
	for _, name := range names {
		desc, err := findField(name, fields)
		if err != nil {
			if ignoreMissing {
				log.Warningf("Skipping field %q: %v", name, err)
				continue
			}
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
