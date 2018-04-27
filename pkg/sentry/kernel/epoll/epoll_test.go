// Copyright 2018 Google Inc.
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

package epoll

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/filetest"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

func TestFileDestroyed(t *testing.T) {
	f := filetest.NewTestFile(t)
	id := FileIdentifier{f, 12}

	efile := NewEventPoll(contexttest.Context(t))
	e := efile.FileOperations.(*EventPoll)
	if err := e.AddEntry(id, 0, waiter.EventIn, [2]int32{}); err != nil {
		t.Fatalf("addEntry failed: %v", err)
	}

	// Check that we get an event reported twice in a row.
	evt := e.ReadEvents(1)
	if len(evt) != 1 {
		t.Fatalf("Unexpected number of ready events: want %v, got %v", 1, len(evt))
	}

	evt = e.ReadEvents(1)
	if len(evt) != 1 {
		t.Fatalf("Unexpected number of ready events: want %v, got %v", 1, len(evt))
	}

	// Destroy the file. Check that we get no more events.
	f.DecRef()

	evt = e.ReadEvents(1)
	if len(evt) != 0 {
		t.Fatalf("Unexpected number of ready events: want %v, got %v", 0, len(evt))
	}

}
