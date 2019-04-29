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

package state

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"time"
)

type statEntry struct {
	count uint
	total time.Duration
}

// Stats tracks encode / decode timing.
//
// This currently provides a meaningful String function and no other way to
// extract stats about individual types.
//
// All exported receivers accept nil.
type Stats struct {
	// byType contains a breakdown of time spent by type.
	byType map[reflect.Type]*statEntry

	// stack contains objects in progress.
	stack []reflect.Type

	// last is the last start time.
	last time.Time
}

// sample adds the samples to the given object.
func (s *Stats) sample(typ reflect.Type) {
	now := time.Now()
	s.byType[typ].total += now.Sub(s.last)
	s.last = now
}

// Add adds a sample count.
func (s *Stats) Add(obj reflect.Value) {
	if s == nil {
		return
	}
	if s.byType == nil {
		s.byType = make(map[reflect.Type]*statEntry)
	}
	typ := obj.Type()
	entry, ok := s.byType[typ]
	if !ok {
		entry = new(statEntry)
		s.byType[typ] = entry
	}
	entry.count++
}

// Remove removes a sample count. It should only be called after a previous
// Add().
func (s *Stats) Remove(obj reflect.Value) {
	if s == nil {
		return
	}
	typ := obj.Type()
	entry := s.byType[typ]
	entry.count--
}

// Start starts a sample.
func (s *Stats) Start(obj reflect.Value) {
	if s == nil {
		return
	}
	if len(s.stack) > 0 {
		last := s.stack[len(s.stack)-1]
		s.sample(last)
	} else {
		// First time sample.
		s.last = time.Now()
	}
	s.stack = append(s.stack, obj.Type())
}

// Done finishes the current sample.
func (s *Stats) Done() {
	if s == nil {
		return
	}
	last := s.stack[len(s.stack)-1]
	s.sample(last)
	s.stack = s.stack[:len(s.stack)-1]
}

type sliceEntry struct {
	typ   reflect.Type
	entry *statEntry
}

// String returns a table representation of the stats.
func (s *Stats) String() string {
	if s == nil || len(s.byType) == 0 {
		return "(no data)"
	}

	// Build a list of stat entries.
	ss := make([]sliceEntry, 0, len(s.byType))
	for typ, entry := range s.byType {
		ss = append(ss, sliceEntry{
			typ:   typ,
			entry: entry,
		})
	}

	// Sort by total time (descending).
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].entry.total > ss[j].entry.total
	})

	// Print the stat results.
	var (
		buf   bytes.Buffer
		count uint
		total time.Duration
	)
	buf.WriteString("\n")
	buf.WriteString(fmt.Sprintf("%12s | %8s | %8s | %s\n", "total", "count", "per", "type"))
	buf.WriteString("-------------+----------+----------+-------------\n")
	for _, se := range ss {
		count += se.entry.count
		total += se.entry.total
		per := se.entry.total / time.Duration(se.entry.count)
		buf.WriteString(fmt.Sprintf("%12s | %8d | %8s | %s\n",
			se.entry.total, se.entry.count, per, se.typ.String()))
	}
	buf.WriteString("-------------+----------+----------+-------------\n")
	buf.WriteString(fmt.Sprintf("%12s | %8d | %8s | [all]",
		total, count, total/time.Duration(count)))
	return string(buf.Bytes())
}
