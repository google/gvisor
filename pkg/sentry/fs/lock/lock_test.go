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

package lock

import (
	"reflect"
	"testing"
)

type entry struct {
	Lock
	LockRange
}

func equals(e0, e1 []entry) bool {
	if len(e0) != len(e1) {
		return false
	}
	for i := range e0 {
		for k := range e0[i].Lock.Readers {
			if !e1[i].Lock.Readers[k] {
				return false
			}
		}
		for k := range e1[i].Lock.Readers {
			if !e0[i].Lock.Readers[k] {
				return false
			}
		}
		if !reflect.DeepEqual(e0[i].LockRange, e1[i].LockRange) {
			return false
		}
		if e0[i].Lock.HasWriter != e1[i].Lock.HasWriter {
			return false
		}
		if e0[i].Lock.Writer != e1[i].Lock.Writer {
			return false
		}
	}
	return true
}

// fill a LockSet with consecutive region locks.  Will panic if
// LockRanges are not consecutive.
func fill(entries []entry) LockSet {
	l := LockSet{}
	for _, e := range entries {
		gap := l.FindGap(e.LockRange.Start)
		if !gap.Ok() {
			panic("cannot insert into existing segment")
		}
		l.Insert(gap, e.LockRange, e.Lock)
	}
	return l
}

func TestCanLockEmpty(t *testing.T) {
	l := LockSet{}

	// Expect to be able to take any locks given that the set is empty.
	eof := l.FirstGap().End()
	r := LockRange{0, eof}
	if !l.canLock(1, ReadLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", ReadLock, r, 1)
	}
	if !l.canLock(2, ReadLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", ReadLock, r, 2)
	}
	if !l.canLock(1, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", WriteLock, r, 1)
	}
	if !l.canLock(2, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", WriteLock, r, 2)
	}
}

func TestCanLock(t *testing.T) {
	// + -------------- + ---------- + -------------- + --------- +
	// | Readers 1 & 2  | Readers 1  | Readers 1 & 3  | Writer 1  |
	// + -------------  + ---------- + -------------- + --------- +
	// 0             1024         2048             3072        4096
	l := fill([]entry{
		{
			Lock:      Lock{Readers: map[UniqueID]bool{1: true, 2: true}},
			LockRange: LockRange{0, 1024},
		},
		{
			Lock:      Lock{Readers: map[UniqueID]bool{1: true}},
			LockRange: LockRange{1024, 2048},
		},
		{
			Lock:      Lock{Readers: map[UniqueID]bool{1: true, 3: true}},
			LockRange: LockRange{2048, 3072},
		},
		{
			Lock:      Lock{HasWriter: true, Writer: 1},
			LockRange: LockRange{3072, 4096},
		},
	})

	// Now that we have a mildly interesting layout, try some checks on different
	// ranges, uids, and lock types.
	//
	// Expect to be able to extend the read lock, despite the writer lock, because
	// the writer has the same uid as the requested read lock.
	r := LockRange{0, 8192}
	if !l.canLock(1, ReadLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", ReadLock, r, 1)
	}
	// Expect to *not* be able to extend the read lock since there is an overlapping
	// writer region locked by someone other than the uid.
	if l.canLock(2, ReadLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got true, want false", ReadLock, r, 2)
	}
	// Expect to be able to extend the read lock if there are only other readers in
	// the way.
	r = LockRange{64, 3072}
	if !l.canLock(2, ReadLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", ReadLock, r, 2)
	}
	// Expect to be able to set a read lock beyond the range of any existing locks.
	r = LockRange{4096, 10240}
	if !l.canLock(2, ReadLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", ReadLock, r, 2)
	}

	// Expect to not be able to take a write lock with other readers in the way.
	r = LockRange{0, 8192}
	if l.canLock(1, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got true, want false", WriteLock, r, 1)
	}
	// Expect to be able to extend the write lock for the same uid.
	r = LockRange{3072, 8192}
	if !l.canLock(1, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", WriteLock, r, 1)
	}
	// Expect to not be able to overlap a write lock for two different uids.
	if l.canLock(2, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got true, want false", WriteLock, r, 2)
	}
	// Expect to be able to set a write lock that is beyond the range of any
	// existing locks.
	r = LockRange{8192, 10240}
	if !l.canLock(2, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", WriteLock, r, 2)
	}
	// Expect to be able to upgrade a read lock (any portion of it).
	r = LockRange{1024, 2048}
	if !l.canLock(1, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", WriteLock, r, 1)
	}
	r = LockRange{1080, 2000}
	if !l.canLock(1, WriteLock, r) {
		t.Fatalf("canLock type %d for range %v and uid %d got false, want true", WriteLock, r, 1)
	}
}

func TestSetLock(t *testing.T) {
	tests := []struct {
		// description of test.
		name string

		// LockSet entries to pre-fill.
		before []entry

		// Description of region to lock:
		//
		// start is the file offset of the lock.
		start uint64
		// end is the end file offset of the lock.
		end uint64
		// uid of lock attempter.
		uid UniqueID
		// lock type requested.
		lockType LockType

		// success is true if taking the above
		// lock should succeed.
		success bool

		// Expected layout of the set after locking
		// if success is true.
		after []entry
	}{
		{
			name:     "set zero length ReadLock on empty set",
			start:    0,
			end:      0,
			uid:      0,
			lockType: ReadLock,
			success:  true,
		},
		{
			name:     "set zero length WriteLock on empty set",
			start:    0,
			end:      0,
			uid:      0,
			lockType: WriteLock,
			success:  true,
		},
		{
			name:     "set ReadLock on empty set",
			start:    0,
			end:      LockEOF,
			uid:      0,
			lockType: ReadLock,
			success:  true,
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
		},
		{
			name:     "set WriteLock on empty set",
			start:    0,
			end:      LockEOF,
			uid:      0,
			lockType: WriteLock,
			success:  true,
			// + ----------------------------------------- +
			// | Writer  0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, LockEOF},
				},
			},
		},
		{
			name: "set ReadLock on WriteLock same uid",
			// + ----------------------------------------- +
			// | Writer 0                                  |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start:    0,
			end:      4096,
			uid:      0,
			lockType: ReadLock,
			success:  true,
			// + ----------- + --------------------------- +
			// | Readers 0   | Writer 0                    |
			// + ----------- + --------------------------- +
			// 0          4096                    max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, 4096},
				},
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "set WriteLock on ReadLock same uid",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start:    0,
			end:      4096,
			uid:      0,
			lockType: WriteLock,
			success:  true,
			// + ----------- + --------------------------- +
			// | Writer 0    | Readers 0                   |
			// + ----------- + --------------------------- +
			// 0          4096                    max uint64
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "set ReadLock on WriteLock different uid",
			// + ----------------------------------------- +
			// | Writer 0                                  |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start:    0,
			end:      4096,
			uid:      1,
			lockType: ReadLock,
			success:  false,
		},
		{
			name: "set WriteLock on ReadLock different uid",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start:    0,
			end:      4096,
			uid:      1,
			lockType: WriteLock,
			success:  false,
		},
		{
			name: "split ReadLock for overlapping lock at start 0",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start:    0,
			end:      4096,
			uid:      1,
			lockType: ReadLock,
			success:  true,
			// + -------------- + --------------------------- +
			// | Readers 0 & 1  | Readers 0                   |
			// + -------------- + --------------------------- +
			// 0             4096                    max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "split ReadLock for overlapping lock at non-zero start",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start:    4096,
			end:      8192,
			uid:      1,
			lockType: ReadLock,
			success:  true,
			// + ---------- + -------------- + ----------- +
			// | Readers 0  | Readers 0 & 1  | Readers 0   |
			// + ---------- + -------------- + ----------- +
			// 0         4096             8192    max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{4096, 8192},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{8192, LockEOF},
				},
			},
		},
		{
			name: "fill front gap with ReadLock",
			// + --------- + ---------------------------- +
			// | gap       | Readers 0                    |
			// + --------- + ---------------------------- +
			// 0        1024                     max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, LockEOF},
				},
			},
			start:    0,
			end:      8192,
			uid:      0,
			lockType: ReadLock,
			success:  true,
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
		},
		{
			name: "fill end gap with ReadLock",
			// + ---------------------------- +
			// | Readers 0                    |
			// + ---------------------------- +
			// 0                           4096
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, 4096},
				},
			},
			start:    1024,
			end:      LockEOF,
			uid:      0,
			lockType: ReadLock,
			success:  true,
			// Note that this is not merged after lock does a Split.  This is
			// fine because the two locks will still *behave* as one.  In other
			// words we can fragment any lock all we want and semantically it
			// makes no difference.
			//
			// + ----------- + --------------------------- +
			// | Readers 0   | Readers 0                   |
			// + ----------- + --------------------------- +
			// 0                                  max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, LockEOF},
				},
			},
		},
		{
			name: "fill gap with ReadLock and split",
			// + --------- + ---------------------------- +
			// | gap       | Readers 0                    |
			// + --------- + ---------------------------- +
			// 0        1024                     max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, LockEOF},
				},
			},
			start:    0,
			end:      4096,
			uid:      1,
			lockType: ReadLock,
			success:  true,
			// + --------- + ------------- + ------------- +
			// | Reader 1  | Readers 0 & 1 | Reader 0      |
			// + ----------+ ------------- + ------------- +
			// 0        1024            4096      max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{1024, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "upgrade ReadLock to WriteLock for single uid fill gap",
			// + ------------- + --------- + --- + ------------- +
			// | Readers 0 & 1 | Readers 0 | gap | Readers 0 & 2 |
			// + ------------- + --------- + --- + ------------- +
			// 0            1024        2048  4096      max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, 2048},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
			start:    1024,
			end:      4096,
			uid:      0,
			lockType: WriteLock,
			success:  true,
			// + ------------- + -------- + ------------- +
			// | Readers 0 & 1 | Writer 0 | Readers 0 & 2 |
			// + ------------- + -------- + ------------- +
			// 0            1024       4096      max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{1024, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "upgrade ReadLock to WriteLock for single uid keep gap",
			// + ------------- + --------- + --- + ------------- +
			// | Readers 0 & 1 | Readers 0 | gap | Readers 0 & 2 |
			// + ------------- + --------- + --- + ------------- +
			// 0            1024        2048  4096      max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, 2048},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
			start:    1024,
			end:      3072,
			uid:      0,
			lockType: WriteLock,
			success:  true,
			// + ------------- + -------- + --- + ------------- +
			// | Readers 0 & 1 | Writer 0 | gap | Readers 0 & 2 |
			// + ------------- + -------- + --- + ------------- +
			// 0            1024       3072  4096      max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{1024, 3072},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "fail to upgrade ReadLock to WriteLock with conflicting Reader",
			// + ------------- + --------- +
			// | Readers 0 & 1 | Readers 0 |
			// + ------------- + --------- +
			// 0            1024        2048
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, 2048},
				},
			},
			start:    0,
			end:      2048,
			uid:      0,
			lockType: WriteLock,
			success:  false,
		},
		{
			name: "take WriteLock on whole file if all uids are the same",
			// + ------------- + --------- + --------- + ---------- +
			// | Writer 0      | Readers 0 | Readers 0 | Readers 0  |
			// + ------------- + --------- + --------- + ---------- +
			// 0            1024        2048        4096   max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{1024, 2048},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{2048, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
			start:    0,
			end:      LockEOF,
			uid:      0,
			lockType: WriteLock,
			success:  true,
			// We do not manually merge locks.  Semantically a fragmented lock
			// held by the same uid will behave as one lock so it makes no difference.
			//
			// + ------------- + ---------------------------- +
			// | Writer 0      | Writer 0                     |
			// + ------------- + ---------------------------- +
			// 0            1024                     max uint64
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{1024, LockEOF},
				},
			},
		},
	}

	for _, test := range tests {
		l := fill(test.before)

		r := LockRange{Start: test.start, End: test.end}
		success := l.lock(test.uid, test.lockType, r)
		var got []entry
		for seg := l.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			got = append(got, entry{
				Lock:      seg.Value(),
				LockRange: seg.Range(),
			})
		}

		if success != test.success {
			t.Errorf("%s: setlock(%v, %+v, %d, %d) got success %v, want %v", test.name, test.before, r, test.uid, test.lockType, success, test.success)
			continue
		}

		if success {
			if !equals(got, test.after) {
				t.Errorf("%s: got set %+v, want %+v", test.name, got, test.after)
			}
		}
	}
}

func TestUnlock(t *testing.T) {
	tests := []struct {
		// description of test.
		name string

		// LockSet entries to pre-fill.
		before []entry

		// Description of region to unlock:
		//
		// start is the file start of the lock.
		start uint64
		// end is the end file start of the lock.
		end uint64
		// uid of lock holder.
		uid UniqueID

		// Expected layout of the set after unlocking.
		after []entry
	}{
		{
			name:  "unlock zero length on empty set",
			start: 0,
			end:   0,
			uid:   0,
		},
		{
			name:  "unlock on empty set (no-op)",
			start: 0,
			end:   LockEOF,
			uid:   0,
		},
		{
			name: "unlock uid not locked (no-op)",
			// + --------------------------- +
			// | Readers 1 & 2               |
			// + --------------------------- +
			// 0                    max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true, 2: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 1024,
			end:   4096,
			uid:   0,
			// + --------------------------- +
			// | Readers 1 & 2               |
			// + --------------------------- +
			// 0                    max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true, 2: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
		},
		{
			name: "unlock ReadLock over entire file",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 0,
			end:   LockEOF,
			uid:   0,
		},
		{
			name: "unlock WriteLock over entire file",
			// + ----------------------------------------- +
			// | Writer 0                                  |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 0,
			end:   LockEOF,
			uid:   0,
		},
		{
			name: "unlock partial ReadLock (start)",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 0,
			end:   4096,
			uid:   0,
			// + ------ + --------------------------- +
			// | gap    | Readers 0                   |
			// +------- + --------------------------- +
			// 0     4096                    max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "unlock partial WriteLock (start)",
			// + ----------------------------------------- +
			// | Writer  0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 0,
			end:   4096,
			uid:   0,
			// + ------ + --------------------------- +
			// | gap    | Writer  0                   |
			// +------- + --------------------------- +
			// 0     4096                    max uint64
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "unlock partial ReadLock (end)",
			// + ----------------------------------------- +
			// | Readers 0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 4096,
			end:   LockEOF,
			uid:   0,
			// + --------------------------- +
			// | Readers 0                   |
			// +---------------------------- +
			// 0                          4096
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true}},
					LockRange: LockRange{0, 4096},
				},
			},
		},
		{
			name: "unlock partial WriteLock (end)",
			// + ----------------------------------------- +
			// | Writer  0                                 |
			// + ----------------------------------------- +
			// 0                                  max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 4096,
			end:   LockEOF,
			uid:   0,
			// + --------------------------- +
			// | Writer  0                   |
			// +---------------------------- +
			// 0                          4096
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 4096},
				},
			},
		},
		{
			name: "unlock for single uid",
			// + ------------- + --------- + ------------------- +
			// | Readers 0 & 1 | Writer 0  | Readers 0 & 1 & 2   |
			// + ------------- + --------- + ------------------- +
			// 0            1024        4096            max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{1024, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
			start: 0,
			end:   LockEOF,
			uid:   0,
			// + --------- + --- + --------------- +
			// | Readers 1 | gap | Readers 1 & 2   |
			// + --------- + --- + --------------- +
			// 0        1024  4096        max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "unlock subsection locked",
			// + ------------------------------- +
			// | Readers 0 & 1 & 2               |
			// + ------------------------------- +
			// 0                        max uint64
			before: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true, 2: true}},
					LockRange: LockRange{0, LockEOF},
				},
			},
			start: 1024,
			end:   4096,
			uid:   0,
			// + ----------------- + ------------- + ----------------- +
			// | Readers 0 & 1 & 2 | Readers 1 & 2 | Readers 0 & 1 & 2 |
			// + ----------------- + ------------- + ----------------- +
			// 0                1024            4096          max uint64
			after: []entry{
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true, 2: true}},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true, 2: true}},
					LockRange: LockRange{1024, 4096},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true, 2: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "unlock mid-gap to increase gap",
			// + --------- + ----- + ------------------- +
			// | Writer 0  |  gap  | Readers 0 & 1       |
			// + --------- + ----- + ------------------- +
			// 0        1024    4096            max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
			start: 8,
			end:   2048,
			uid:   0,
			// + --------- + ----- + ------------------- +
			// | Writer 0  |  gap  | Readers 0 & 1       |
			// + --------- + ----- + ------------------- +
			// 0           8    4096            max uint64
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 8},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
		},
		{
			name: "unlock split region on uid mid-gap",
			// + --------- + ----- + ------------------- +
			// | Writer 0  |  gap  | Readers 0 & 1       |
			// + --------- + ----- + ------------------- +
			// 0        1024    4096            max uint64
			before: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{4096, LockEOF},
				},
			},
			start: 2048,
			end:   8192,
			uid:   0,
			// + --------- + ----- + --------- + ------------- +
			// | Writer 0  |  gap  | Readers 1 | Readers 0 & 1 |
			// + --------- + ----- + --------- + ------------- +
			// 0       1024     4096        8192      max uint64
			after: []entry{
				{
					Lock:      Lock{HasWriter: true, Writer: 0},
					LockRange: LockRange{0, 1024},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{1: true}},
					LockRange: LockRange{4096, 8192},
				},
				{
					Lock:      Lock{Readers: map[UniqueID]bool{0: true, 1: true}},
					LockRange: LockRange{8192, LockEOF},
				},
			},
		},
	}

	for _, test := range tests {
		l := fill(test.before)

		r := LockRange{Start: test.start, End: test.end}
		l.unlock(test.uid, r)
		var got []entry
		for seg := l.FirstSegment(); seg.Ok(); seg = seg.NextSegment() {
			got = append(got, entry{
				Lock:      seg.Value(),
				LockRange: seg.Range(),
			})
		}
		if !equals(got, test.after) {
			t.Errorf("%s: got set %+v, want %+v", test.name, got, test.after)
		}
	}
}
