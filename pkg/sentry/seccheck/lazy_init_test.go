// Copyright 2026 The gVisor Authors.
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
	"testing"

	"gvisor.dev/gvisor/pkg/fd"
)

// TestLazyInitialization checks that Points is filled only when a trace
// session enables points. This test must run in its own test binary, because
// other tests call Initialize in TestMain.
func TestLazyInitialization(t *testing.T) {
	if len(Points) != 0 {
		t.Fatalf("Points filled before first use, with %d points", len(Points))
	}

	// A session with sinks but without points does not need Points.
	RegisterSink(SinkDesc{
		Name: "lazy-test-sink",
		New: func(map[string]any, *fd.FD) (Sink, error) {
			return sinkDefaultsImpl{}, nil
		},
	})
	conf := SessionConfig{
		Name:  DefaultSessionName,
		Sinks: []SinkConfig{{Name: "lazy-test-sink"}},
	}
	if err := Create(&conf, false); err != nil {
		t.Fatalf("Create(%+v): %v", conf, err)
	}
	if err := Delete(conf.Name); err != nil {
		t.Fatalf("Delete(%q): %v", conf.Name, err)
	}
	if len(Points) != 0 {
		t.Fatalf("Points filled for a session without points, with %d points", len(Points))
	}

	const point = "syscall/openat/enter"
	conf.Points = []PointConfig{
		{
			Name:           point,
			OptionalFields: []string{"fd_path"},
			ContextFields:  []string{"time"},
		},
		{Name: "syscall/sysno/0/enter"},
	}
	if err := Create(&conf, false); err != nil {
		t.Fatalf("Create(%+v): %v", conf, err)
	}
	if err := Delete(conf.Name); err != nil {
		t.Fatalf("Delete(%q): %v", conf.Name, err)
	}
	if _, ok := Points[point]; !ok {
		t.Errorf("point %q not in Points after Create", point)
	}
}
