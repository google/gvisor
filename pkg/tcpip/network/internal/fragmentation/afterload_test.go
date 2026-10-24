// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fragmentation

import (
	"bytes"
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type restoreClock struct {
	now   time.Duration
	timer *restoreTimer
}

var _ tcpip.Clock = (*restoreClock)(nil)

func (*restoreClock) StateTypeName() string {
	return "gvisor.dev/gvisor/pkg/tcpip/network/internal/fragmentation.restoreClock"
}

func (*restoreClock) StateFields() []string {
	return []string{"now"}
}

func (c *restoreClock) StateSave(s state.Sink) {
	s.Save(0, &c.now)
}

func (c *restoreClock) StateLoad(_ context.Context, s state.Source) {
	s.Load(0, &c.now)
}

func (c *restoreClock) Now() time.Time {
	return time.Unix(0, int64(c.now))
}

func (c *restoreClock) NowMonotonic() tcpip.MonotonicTime {
	return tcpip.MonotonicTime{}.Add(c.now)
}

func (c *restoreClock) AfterFunc(d time.Duration, fn func()) tcpip.Timer {
	t := &restoreTimer{
		clock:  c,
		delay:  d,
		fn:     fn,
		active: true,
	}
	c.timer = t
	return t
}

func (c *restoreClock) runNext() bool {
	t := c.timer
	if t == nil || !t.active {
		return false
	}
	t.active = false
	c.now += t.delay
	done := make(chan struct{})
	go func() {
		t.fn()
		close(done)
	}()
	<-done
	return true
}

type restoreTimer struct {
	clock  *restoreClock
	delay  time.Duration
	fn     func()
	active bool
}

var _ tcpip.Timer = (*restoreTimer)(nil)

func (t *restoreTimer) Stop() bool {
	wasActive := t.active
	t.active = false
	return wasActive
}

func (t *restoreTimer) Reset(d time.Duration) {
	t.delay = d
	t.active = true
	t.clock.timer = t
}

func init() {
	state.Register((*restoreClock)(nil))
}

// TestFragmentationReleaseJobAfterLoad verifies that after state save/load the
// release job is rebound and rescheduled for an in-progress reassembly.
func TestFragmentationReleaseJobAfterLoad(t *testing.T) {
	const timeout = time.Second
	clock := &restoreClock{}
	f := NewFragmentation(minBlockSize, HighFragThreshold, LowFragThreshold, timeout, clock, nil)
	defer f.Release()

	id := FragmentID{ID: 1}
	pkt := pkt(1, "x")
	out, _, done, err := f.Process(id, 0, 0, true, 17, pkt)
	pkt.DecRef()
	if err != nil {
		if out != nil {
			out.DecRef()
		}
		t.Fatalf("Process: %v", err)
	}
	if out != nil {
		out.DecRef()
		t.Fatal("Process returned a packet; want nil")
	}
	if done {
		t.Fatal("Process returned done=true; want false")
	}

	var saved bytes.Buffer
	ctx := context.Background()
	if _, err := state.Save(ctx, &saved, f); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	f.Release()

	var loaded Fragmentation
	if _, err := state.Load(ctx, bytes.NewReader(saved.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	defer loaded.Release()

	loadedClock, ok := loaded.clock.(*restoreClock)
	if !ok {
		t.Fatalf("loaded.clock has type %T, want *restoreClock", loaded.clock)
	}
	if !loadedClock.runNext() {
		t.Fatal("release job was not rescheduled after restore")
	}

	loaded.mu.Lock()
	_, ok = loaded.reassemblers[id]
	loaded.mu.Unlock()
	if ok {
		t.Error("reassembler was not released after its restored timeout expired")
	}
}
