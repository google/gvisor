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

package seqatomic

import (
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/syncutil"
)

func TestSeqAtomicLoadUncontended(t *testing.T) {
	var seq syncutil.SeqCount
	const want = 1
	data := want
	if got := SeqAtomicLoadInt(&seq, &data); got != want {
		t.Errorf("SeqAtomicLoadInt: got %v, wanted %v", got, want)
	}
}

func TestSeqAtomicLoadAfterWrite(t *testing.T) {
	var seq syncutil.SeqCount
	var data int
	const want = 1
	seq.BeginWrite()
	data = want
	seq.EndWrite()
	if got := SeqAtomicLoadInt(&seq, &data); got != want {
		t.Errorf("SeqAtomicLoadInt: got %v, wanted %v", got, want)
	}
}

func TestSeqAtomicLoadDuringWrite(t *testing.T) {
	var seq syncutil.SeqCount
	var data int
	const want = 1
	seq.BeginWrite()
	go func() {
		time.Sleep(time.Second)
		data = want
		seq.EndWrite()
	}()
	if got := SeqAtomicLoadInt(&seq, &data); got != want {
		t.Errorf("SeqAtomicLoadInt: got %v, wanted %v", got, want)
	}
}

func TestSeqAtomicTryLoadUncontended(t *testing.T) {
	var seq syncutil.SeqCount
	const want = 1
	data := want
	epoch := seq.BeginRead()
	if got, ok := SeqAtomicTryLoadInt(&seq, epoch, &data); !ok || got != want {
		t.Errorf("SeqAtomicTryLoadInt: got (%v, %v), wanted (%v, true)", got, ok, want)
	}
}

func TestSeqAtomicTryLoadDuringWrite(t *testing.T) {
	var seq syncutil.SeqCount
	var data int
	epoch := seq.BeginRead()
	seq.BeginWrite()
	if got, ok := SeqAtomicTryLoadInt(&seq, epoch, &data); ok {
		t.Errorf("SeqAtomicTryLoadInt: got (%v, true), wanted (_, false)", got)
	}
	seq.EndWrite()
}

func TestSeqAtomicTryLoadAfterWrite(t *testing.T) {
	var seq syncutil.SeqCount
	var data int
	epoch := seq.BeginRead()
	seq.BeginWrite()
	seq.EndWrite()
	if got, ok := SeqAtomicTryLoadInt(&seq, epoch, &data); ok {
		t.Errorf("SeqAtomicTryLoadInt: got (%v, true), wanted (_, false)", got)
	}
}

func BenchmarkSeqAtomicLoadIntUncontended(b *testing.B) {
	var seq syncutil.SeqCount
	const want = 42
	data := want
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if got := SeqAtomicLoadInt(&seq, &data); got != want {
				b.Fatalf("SeqAtomicLoadInt: got %v, wanted %v", got, want)
			}
		}
	})
}

func BenchmarkSeqAtomicTryLoadIntUncontended(b *testing.B) {
	var seq syncutil.SeqCount
	const want = 42
	data := want
	b.RunParallel(func(pb *testing.PB) {
		epoch := seq.BeginRead()
		for pb.Next() {
			if got, ok := SeqAtomicTryLoadInt(&seq, epoch, &data); !ok || got != want {
				b.Fatalf("SeqAtomicTryLoadInt: got (%v, %v), wanted (%v, true)", got, ok, want)
			}
		}
	})
}

// For comparison:
func BenchmarkAtomicValueLoadIntUncontended(b *testing.B) {
	var a atomic.Value
	const want = 42
	a.Store(int(want))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if got := a.Load().(int); got != want {
				b.Fatalf("atomic.Value.Load: got %v, wanted %v", got, want)
			}
		}
	})
}
