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
	"strings"
	"testing"
)

func TestLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf SessionConfig
	}{
		{
			name: "all-fields",
			conf: SessionConfig{
				Name: "Default",
				Points: []PointConfig{
					{
						Name: "syscall/sysno/0/enter",
					},
					{
						Name:           "syscall/openat/enter",
						OptionalFields: []string{"fd_path"},
					},
					{
						Name:          "syscall/sysno/1/enter",
						ContextFields: []string{"time"},
					},
					{
						Name:           "syscall/openat/enter",
						OptionalFields: []string{"fd_path"},
						ContextFields:  []string{"time"},
					},
				},
				Sinks: []SinkConfig{
					{Name: "test-sink"},
				},
			},
		},
		{
			name: "no-sink",
			conf: SessionConfig{
				Name: "Default",
				Points: []PointConfig{
					{Name: "syscall/sysno/0/enter"},
				},
			},
		},
		{
			name: "no-points",
			conf: SessionConfig{
				Name: "Default",
				Sinks: []SinkConfig{
					{Name: "test-sink"},
				},
			},
		},
		{
			name: "ignore-errors",
			conf: SessionConfig{
				Name:          "Default",
				IgnoreMissing: true,
				Points: []PointConfig{
					{
						Name: "foobar",
					},
					{
						Name:          "syscall/sysno/1/enter",
						ContextFields: []string{"foobar"},
					},
					{
						Name:          "syscall/openat/enter",
						ContextFields: []string{"foobar"},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Create(&tc.conf, false); err != nil {
				t.Errorf("Create(): %v", err)
			}

			var got []SessionConfig
			List(&got)
			if len(got) != 1 {
				t.Errorf("only one session should exist, got: %d", len(got))
			} else {
				if got[0].Name != tc.conf.Name {
					t.Errorf("wrong name, want: %q, got: %q", tc.conf.Name, got[0].Name)
				}
			}

			if err := Delete(tc.conf.Name); err != nil {
				t.Errorf("Delete(%q): %v", tc.conf.Name, err)
			}
		})
	}
}

func TestFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf SessionConfig
		err  string
	}{
		{
			name: "point",
			err:  `point "foobar" not found`,
			conf: SessionConfig{
				Name: "Default",
				Points: []PointConfig{
					{Name: "foobar"},
				},
			},
		},
		{
			name: "optional-field",
			err:  `field "foobar" not found`,
			conf: SessionConfig{
				Name: "Default",
				Points: []PointConfig{
					{
						Name:           "syscall/openat/enter",
						OptionalFields: []string{"foobar"},
					},
				},
			},
		},
		{
			name: "context-field",
			err:  `field "foobar" not found`,
			conf: SessionConfig{
				Name: "Default",
				Points: []PointConfig{
					{
						Name:          "syscall/sysno/1/enter",
						ContextFields: []string{"foobar"},
					},
				},
			},
		},
		{
			name: "sink",
			err:  `sink "foobar" not found`,
			conf: SessionConfig{
				Name: "Default",
				Sinks: []SinkConfig{
					{Name: "foobar"},
				},
			},
		},
		{
			name: "sink-ignore-missing",
			err:  `sink "foobar" not found`,
			conf: SessionConfig{
				Name:          "Default",
				IgnoreMissing: true,
				Sinks: []SinkConfig{
					{Name: "foobar"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Create(&tc.conf, false)
			if err == nil {
				_ = Delete(tc.conf.Name)
				t.Fatal("Create() should have failed")
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("invalid error, want: %q, got: %q", tc.err, err)
			}
		})
	}
}
