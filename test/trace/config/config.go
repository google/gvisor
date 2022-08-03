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

// Package config providides helper functions to configure trace sessions.
package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/runsc/boot"
)

// Builder helps with building of trace session configuration.
type Builder struct {
	points []seccheck.PointConfig
	sinks  []seccheck.SinkConfig
}

// WriteInitConfig writes the current configuration in a format compatible with
// the flag --pod-init-config.
func (b *Builder) WriteInitConfig(w io.Writer) error {
	init := &boot.InitConfig{
		TraceSession: seccheck.SessionConfig{
			Name:   seccheck.DefaultSessionName,
			Points: b.points,
			Sinks:  b.sinks,
		},
	}

	encoder := json.NewEncoder(w)
	return encoder.Encode(&init)
}

// LoadAllPoints enables all points together with all optional and context
// fields.
func (b *Builder) LoadAllPoints(runscPath string) error {
	cmd := exec.Command(runscPath, "trace", "metadata")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	// The command above produces an output like the following:
	//   POINTS (907)
	//   Name: container/start, optional fields: [], context fields: [time|thread_id]
	//
	//   SINKS (2)
	//   Name: remote
	scanner := bufio.NewScanner(bytes.NewReader(out))
	if !scanner.Scan() {
		return fmt.Errorf("%q returned empty", cmd)
	}
	if line := scanner.Text(); !strings.HasPrefix(line, "POINTS (") {
		return fmt.Errorf("%q missing POINTS header: %q", cmd, line)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue // Skip empty lines.
		}
		if strings.HasPrefix(line, "SINKS (") {
			break // Starting SINKS section, POINTS section is over.
		}
		elems := strings.Split(line, ",")
		if len(elems) != 3 {
			return fmt.Errorf("invalid line: %q", line)
		}
		name := strings.TrimPrefix(elems[0], "Name: ")
		optFields, err := parseFields(elems[1], "optional fields: ")
		if err != nil {
			return err
		}
		ctxFields, err := parseFields(elems[2], "context fields: ")
		if err != nil {
			return err
		}
		b.points = append(b.points, seccheck.PointConfig{
			Name:           name,
			OptionalFields: optFields,
			ContextFields:  ctxFields,
		})
	}
	if len(b.points) == 0 {
		return fmt.Errorf("%q returned no points", cmd)
	}
	return scanner.Err()
}

func parseFields(elem, prefix string) ([]string, error) {
	stripped := strings.TrimPrefix(strings.TrimSpace(elem), prefix)
	switch {
	case len(stripped) < 2:
		return nil, fmt.Errorf("invalid %s format: %q", prefix, elem)
	case len(stripped) == 2:
		return nil, nil
	}
	// Remove [] from `stripped`.
	clean := stripped[1 : len(stripped)-1]
	return strings.Split(clean, "|"), nil
}

// AddSink adds the sink to the configuration.
func (b *Builder) AddSink(sink seccheck.SinkConfig) {
	b.sinks = append(b.sinks, sink)
}
