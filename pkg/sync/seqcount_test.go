// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync

import (
	"testing"
	"time"
)

func TestSeqCountWriteUncontended(t *testing.T) {
	var seq SeqCount
	seq.BeginWrite()
	seq.EndWrite()
}

func TestSeqCountReadUncontended(t *testing.T) {
	var seq SeqCount
	epoch := seq.BeginRead()
	if !seq.ReadOk(epoch) {
		t.Errorf("ReadOk: got false, wanted true")
	}
}

func TestSeqCountBeginReadAfterWrite(t *testing.T) {
	var seq SeqCount
	var data int32
	const want = 1
	seq.BeginWrite()
	data = want
	seq.EndWrite()
	epoch := seq.BeginRead()
	if data != want {
		t.Errorf("Reader: got %v, wanted %v", data, want)
	}
	if !seq.ReadOk(epoch) {
		t.Errorf("ReadOk: got false, wanted true")
	}
}

func TestSeqCountBeginReadDuringWrite(t *testing.T) {
	var seq SeqCount
	var data int
	const want = 1
	seq.BeginWrite()
	go func() {
		time.Sleep(time.Second)
		data = want
		seq.EndWrite()
	}()
	epoch := seq.BeginRead()
	if data != want {
		t.Errorf("Reader: got %v, wanted %v", data, want)
	}
	if !seq.ReadOk(epoch) {
		t.Errorf("ReadOk: got false, wanted true")
	}
}

func TestSeqCountReadOkAfterWrite(t *testing.T) {
	var seq SeqCount
	epoch := seq.BeginRead()
	seq.BeginWrite()
	seq.EndWrite()
	if seq.ReadOk(epoch) {
		t.Errorf("ReadOk: got true, wanted false")
	}
}

func TestSeqCountReadOkDuringWrite(t *testing.T) {
	var seq SeqCount
	epoch := seq.BeginRead()
	seq.BeginWrite()
	if seq.ReadOk(epoch) {
		t.Errorf("ReadOk: got true, wanted false")
	}
	seq.EndWrite()
}

func BenchmarkSeqCountWriteUncontended(b *testing.B) {
	var seq SeqCount
	for i := 0; i < b.N; i++ {
		seq.BeginWrite()
		seq.EndWrite()
	}
}

func BenchmarkSeqCountReadUncontended(b *testing.B) {
	var seq SeqCount
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			epoch := seq.BeginRead()
			if !seq.ReadOk(epoch) {
				b.Fatalf("ReadOk: got false, wanted true")
			}
		}
	})
}
