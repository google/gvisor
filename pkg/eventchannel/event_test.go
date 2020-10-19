// Copyright 2019 The gVisor Authors.
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

package eventchannel

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/sync"
)

// testEmitter is an emitter that can be used in tests. It records all events
// emitted, and whether it has been closed.
type testEmitter struct {
	// mu protects all fields below.
	mu sync.Mutex

	// events contains all emitted events.
	events []proto.Message

	// closed records whether Close() was called.
	closed bool
}

// Emit implements Emitter.Emit.
func (te *testEmitter) Emit(msg proto.Message) (bool, error) {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.events = append(te.events, msg)
	return false, nil
}

// Close implements Emitter.Close.
func (te *testEmitter) Close() error {
	te.mu.Lock()
	defer te.mu.Unlock()
	if te.closed {
		return fmt.Errorf("closed called twice")
	}
	te.closed = true
	return nil
}

// testMessage implements proto.Message for testing.
type testMessage struct {
	proto.Message

	// name is the name of the message, used by tests to compare messages.
	name string
}

func TestMultiEmitter(t *testing.T) {
	// Create three testEmitters, tied together in a multiEmitter.
	me := &multiEmitter{}
	var emitters []*testEmitter
	for i := 0; i < 3; i++ {
		te := &testEmitter{}
		emitters = append(emitters, te)
		me.AddEmitter(te)
	}

	// Emit three messages to multiEmitter.
	names := []string{"foo", "bar", "baz"}
	for _, name := range names {
		m := testMessage{name: name}
		if _, err := me.Emit(m); err != nil {
			t.Fatalf("me.Emit(%v) failed: %v", m, err)
		}
	}

	// All three emitters should have all three events.
	for _, te := range emitters {
		if got, want := len(te.events), len(names); got != want {
			t.Fatalf("emitter got %d events, want %d", got, want)
		}
		for i, name := range names {
			if got := te.events[i].(testMessage).name; got != name {
				t.Errorf("emitter got message with name %q, want %q", got, name)
			}
		}
	}

	// Close multiEmitter.
	if err := me.Close(); err != nil {
		t.Fatalf("me.Close() failed: %v", err)
	}

	// All testEmitters should be closed.
	for _, te := range emitters {
		if !te.closed {
			t.Errorf("te.closed got false, want true")
		}
	}
}

func TestRateLimitedEmitter(t *testing.T) {
	// Create a RateLimittedEmitter that wraps a testEmitter.
	te := &testEmitter{}
	max := float64(5) // events per second
	burst := 10       // events
	rle := RateLimitedEmitterFrom(te, max, burst)

	// Send 50 messages in one shot.
	for i := 0; i < 50; i++ {
		if _, err := rle.Emit(testMessage{}); err != nil {
			t.Fatalf("rle.Emit failed: %v", err)
		}
	}

	// We should have received only 10 messages.
	if got, want := len(te.events), 10; got != want {
		t.Errorf("got %d events, want %d", got, want)
	}

	// Sleep for a second and then send another 50.
	time.Sleep(1 * time.Second)
	for i := 0; i < 50; i++ {
		if _, err := rle.Emit(testMessage{}); err != nil {
			t.Fatalf("rle.Emit failed: %v", err)
		}
	}

	// We should have at least 5 more message, plus maybe a few more if the
	// test ran slowly.
	got, wantAtLeast, wantAtMost := len(te.events), 15, 20
	if got < wantAtLeast {
		t.Errorf("got %d events, want at least  %d", got, wantAtLeast)
	}
	if got > wantAtMost {
		t.Errorf("got %d events, want at most %d", got, wantAtMost)
	}
}
