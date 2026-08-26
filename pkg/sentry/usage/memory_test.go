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

package usage

import (
	"sync"
	"testing"
)

func newTestMemory() *MemoryLocked {
	return &MemoryLocked{
		RTMemoryStats:     &RTMemoryStats{},
		MemCgIDToMemStats: make(map[uint32]*memoryStats),
	}
}

// TestIncDecPerCg verifies charge/uncharge correctness for global and per-cgroup
// accounting, including first-seen cgroup creation.
func TestIncDecPerCg(t *testing.T) {
	m := newTestMemory()
	const cg = uint32(7)
	m.Inc(4096, Anonymous, cg)
	m.Inc(8192, Anonymous, cg)
	if got := m.TotalPerCg(cg); got != 12288 {
		t.Errorf("TotalPerCg(cg) = %d, want 12288", got)
	}
	if got := m.Total(); got != 12288 {
		t.Errorf("Total() = %d, want 12288", got)
	}
	m.Dec(4096, Anonymous, cg)
	if got := m.TotalPerCg(cg); got != 8192 {
		t.Errorf("TotalPerCg(cg) after Dec = %d, want 8192", got)
	}
}

// TestTotalPerCgUnknown verifies unknown cgroup ids report zero.
func TestTotalPerCgUnknown(t *testing.T) {
	m := newTestMemory()
	if got := m.TotalPerCg(42); got != 0 {
		t.Errorf("TotalPerCg(unknown) = %d, want 0", got)
	}
	snap, total := m.CopyPerCg(42)
	if total != 0 || snap != (MemoryStats{}) {
		t.Errorf("CopyPerCg(unknown) = %+v, %d, want zero", snap, total)
	}
}

// TestMovePreservesTotal verifies Move keeps the total constant.
func TestMovePreservesTotal(t *testing.T) {
	m := newTestMemory()
	const cg = uint32(3)
	m.Inc(4096, Anonymous, cg)
	m.Move(4096, PageCache, Anonymous, cg)
	snap, total := m.CopyPerCg(cg)
	if total != 4096 || snap.Anonymous != 0 || snap.PageCache != 4096 {
		t.Errorf("after Move: total=%d anon=%d pagecache=%d, want 4096/0/4096",
			total, snap.Anonymous, snap.PageCache)
	}
}

// TestConcurrentIncDecReadRace exercises the RLock/Lock fast/slow paths under -race.
func TestConcurrentIncDecReadRace(t *testing.T) {
	m := newTestMemory()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(cg uint32) {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				m.Inc(4096, Anonymous, cg)
				_ = m.TotalPerCg(cg)
				m.Dec(4096, Anonymous, cg)
			}
		}(uint32(w%4) + 1) // mix shared and distinct cgroup ids
	}
	// Concurrent readers on the global path.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				_, _ = m.Copy()
			}
		}()
	}
	wg.Wait()
}

// BenchmarkIncDecParallel measures charge/uncharge throughput under contention.
// Compare before/after this patch with -test.cpu=1,4,8,16.
func BenchmarkIncDecParallel(b *testing.B) {
	m := newTestMemory()
	m.Inc(1, Anonymous, 1) // pre-create the cgroup so the hot path is RLock-only
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Inc(4096, Anonymous, 1)
			m.Dec(4096, Anonymous, 1)
		}
	})
}

// BenchmarkReadUnderWriteLoad measures reader latency (the watcher's path) while
// writers charge concurrently -- this is the contention P0 removes.
func BenchmarkReadUnderWriteLoad(b *testing.B) {
	m := newTestMemory()
	m.Inc(1, Anonymous, 1)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					m.Inc(4096, Anonymous, 1)
					m.Dec(4096, Anonymous, 1)
				}
			}
		}()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.TotalPerCg(1)
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
}
