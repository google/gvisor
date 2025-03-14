// Copyright 2025 The gVisor Authors.
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

// Package timing provides a way to record the timing of a series of
// operations across one or more goroutines.
package timing

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
)

// Timeline is a series of points in time.
//
// A Timeline always has a defined start time, and will eventually have an end
// time. For this reason, `End` must always be called on a Timeline.
//
// A Timeline may have zero or more mid-points contained between the start and
// end times.
//
// A Timeline may fork to represent other timelines running concurrently. Such
// children Timelines may or may not end later than the parent does.
//
// A single Timeline struct should be owned by a single goroutine at a given
// until it ends (i.e. its endpoint becomes defined), at which point ownership
// transfers to whichever goroutine owns the Timer that created it.
//
// A Timeline may be nil, in which case all methods are no-ops. This means all
// code that takes in a Timeline parameter does not need to check for nilness.
type Timeline struct {
	// name is the name of the Timeline.
	name string

	// timer is the Timer that owns this Timeline.
	timer *Timer

	// start is when the Timeline started.
	start time.Time

	// midpoints is a list of MidPoints that have been reached on this Timeline.
	midpoints []MidPoint

	// end is when the Timeline ended.
	// The zero value means the Timeline has not yet ended.
	end time.Time

	// children is a list of forked timelines that are children of this one.
	// Note that children do not necessarily need to end before the parent does.
	children []*Timeline
}

// MidPoint is a named point in time on a Timeline.
// The starting and ending points of a Timeline are not MidPoints.
type MidPoint struct {
	// when is when the midpoint was reached.
	when time.Time

	// name is the name of the midpoint.
	name string
}

// Reached records a new midpoint on the Timeline.
func (s *Timeline) Reached(name string) {
	if s == nil {
		return
	}
	s.midpoints = append(s.midpoints, MidPoint{
		when: time.Now(),
		name: name,
	})
}

// Fork creates a new Timeline that is a child of this one.
// The returned Timeline is initially owned by the caller, but may be passed
// to another goroutine if desired.
//
// A child timeline may but does not need to end before the parent does.
func (s *Timeline) Fork(name string) *Timeline {
	if s == nil {
		return nil
	}
	s.timer.runningThreads.Add(1)
	sub := &Timeline{
		name:  name,
		timer: s.timer,
		start: time.Now(),
	}
	s.children = append(s.children, sub)
	return sub
}

// traverse appends a flat list of all Timelines in the tree rooted at s
// to the given slice.
func (s *Timeline) traverse(flatTimelines []*Timeline) []*Timeline {
	flatTimelines = append(flatTimelines, s)
	for _, sub := range s.children {
		flatTimelines = sub.traverse(flatTimelines)
	}
	return flatTimelines
}

// End marks the Timeline as having ended. It must be eventually called on all
// Timelines.
// After End is called, the ownership of the Timeline struct moves to the
// goroutine that owns the Timer that created it.
func (s *Timeline) End() {
	if s == nil {
		return
	}
	s.end = time.Now()
	s.timer.runningThreads.Add(-1)
}

// Timer is a root Timeline. It keeps track of one or more running Timelines,
// and can be pretty-printed to show timing information once all Timelines have
// ended.
//
// A Timer struct may move between goroutines, but only one goroutine may own
// it at a time.
//
// A Timer struct may be nil, in which case all methods are no-ops. This means
// all code that takes in a Timer parameter does not need to check for nilness.
type Timer struct {
	// root is the root Timeline of the Timer.
	root *Timeline

	// runningThreads is the number of Timelines that have not yet ended.
	// When dumping timing data, this is used to wait for all Timelines to end.
	runningThreads atomicbitops.Int64
}

// New creates a new Timer.
// The given name is used to identify the Timer in pretty-printed output.
// The given startTime is used as the start time of the Timer's root Timeline.
func New(name string, startTime time.Time) *Timer {
	timer := &Timer{}
	timer.runningThreads.Store(1)
	root := &Timeline{
		name:  name,
		timer: timer,
		start: startTime,
	}
	timer.root = root
	return timer
}

// Reached records a new midpoint on the root Timeline of the Timer.
func (t *Timer) Reached(name string) {
	if t == nil {
		return
	}
	t.root.Reached(name)
}

// Fork creates a new Timeline that is a child of the root Timeline of this
// Timer.
// The returned Timeline is initially owned by the caller, but may be passed
// to another goroutine if desired.
//
// This child timeline may but does not need to end before the root timeline
// does.
func (t *Timer) Fork(name string) *Timeline {
	if t == nil {
		return nil
	}
	return t.root.Fork(name)
}

// End waits for all Timelines owned by this Timer to end, then pretty-prints
// timing information.
// If not all Timelines have ended by the time End is called, End will spin in
// place until they do, and eventually print a warning log if it spins for too
// long (but will not give up).
// End is called implicitly by Log, so it is not necessary to call End
// explicitly unless there is a need to end the root timeline at a different
// time than when logging its data is desired.
func (t *Timer) End() {
	if t == nil {
		return
	}
	if t.root.end.IsZero() {
		t.root.End()
	}
	const (
		stillWaitingLogThreshold = 10 * time.Second
		stillWaitingLogInterval  = 1 * time.Second
	)
	startedWaiting := time.Now()
	var rlLogger log.Logger
	for runningThreads := t.runningThreads.Load(); runningThreads != 0; runningThreads = t.runningThreads.Load() {
		if runningThreads < 0 {
			panic("timing.Timeline.End called too many times in aggregate")
		}
		time.Sleep(1 * time.Millisecond)
		if rlLogger == nil && time.Since(startedWaiting) > stillWaitingLogThreshold {
			rlLogger = log.BasicRateLimitedLogger(stillWaitingLogInterval)
		}
		if rlLogger != nil {
			rlLogger.Warningf("Still waiting for %d threads to finish before collecting %s timing data...", runningThreads, t.root.name)
		}
	}
}

// Log pretty-prints timing information for the root Timeline of the Timer.
// If `t.End` has not yet been called, it will be called implicitly.
// This also means that this function will wait for all child Timelines to end
// before pretty-printing, and will spin in place until this is the case.
// If debug logging is enabled, this function will also log a flat list of
// events that can be easily machine-parsed to the debug log.
func (t *Timer) Log() {
	if t == nil {
		return
	}
	t.End()
	type pointType int
	const (
		pointTypeStart pointType = iota
		pointTypeMid
		pointTypeEnd
	)
	type point struct {
		thread       *Timeline
		pointType    pointType
		midpointName string
	}
	type event struct {
		when  time.Time
		point point
	}
	totalDuration := t.root.end.Sub(t.root.start)
	formatDuration := func(d time.Duration) string {
		switch {
		case totalDuration < time.Second:
			us := d.Microseconds()
			if us >= 1000 {
				return fmt.Sprintf("%d %dµs", us/1000, us%1000)
			}
			return fmt.Sprintf("%dµs", us)
		case totalDuration < 3*time.Minute:
			return fmt.Sprintf("%.3fs", float64(d.Milliseconds())/1000)
		default:
			return d.Truncate(time.Second).String()
		}
	}
	var flatThreads []*Timeline
	var events []event
	for _, thread := range t.root.traverse(nil) {
		flatThreads = append(flatThreads, thread)
		events = append(events, event{when: thread.start, point: point{thread: thread, pointType: pointTypeStart}})
		for _, mid := range thread.midpoints {
			events = append(events, event{when: mid.when, point: point{thread: thread, pointType: pointTypeMid, midpointName: mid.name}})
		}
		events = append(events, event{when: thread.end, point: point{thread: thread, pointType: pointTypeEnd}})
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].when.Before(events[j].when)
	})
	type dedupEvent struct {
		when   time.Time
		points []point
	}
	var dedupEvents []dedupEvent
	for _, e := range events {
		if len(dedupEvents) == 0 || !dedupEvents[len(dedupEvents)-1].when.Equal(e.when) {
			dedupEvents = append(dedupEvents, dedupEvent{when: e.when, points: []point{e.point}})
		} else {
			dedupEvents[len(dedupEvents)-1].points = append(dedupEvents[len(dedupEvents)-1].points, e.point)
		}
	}
	largestInterval := time.Duration(0)
	for i := 1; i < len(dedupEvents); i++ {
		if dedupEvents[i].when.Sub(dedupEvents[i-1].when) > largestInterval {
			largestInterval = dedupEvents[i].when.Sub(dedupEvents[i-1].when)
		}
	}

	rows := make([][]string, len(dedupEvents))
	colWidths := make([]int, len(flatThreads)+3)
	lastTimestampPerThread := make(map[*Timeline]time.Time)
	for i, e := range dedupEvents {
		colData := make([]string, 0, len(flatThreads)+2)
		colData = append(colData, e.when.Format("15:04:05.000000"))
		if i == 0 {
			colData = append(colData, "", "")
		} else {
			sincePrevious := e.when.Sub(dedupEvents[i-1].when)
			colData = append(colData, fmt.Sprintf("+%s", formatDuration(sincePrevious)))
			colData = append(colData, barChart(float64(sincePrevious)/float64(largestInterval), 12))
		}
		for _, thread := range flatThreads {
			lastTimestamp, ok := lastTimestampPerThread[thread]
			if !ok {
				lastTimestamp = thread.start
			}
			threadChanged := false
			for _, p := range e.points {
				if p.thread == thread {
					switch p.pointType {
					case pointTypeStart:
						colData = append(colData, fmt.Sprintf("╭─ %s", thread.name))
					case pointTypeMid:
						colData = append(colData, fmt.Sprintf("├─ %s: %s", p.midpointName, formatDuration(e.when.Sub(lastTimestamp))))
					case pointTypeEnd:
						colData = append(colData, fmt.Sprintf("╰─ END: %s", formatDuration(thread.end.Sub(lastTimestamp))))
					}
					threadChanged = true
					break
				}
			}
			if threadChanged {
				lastTimestampPerThread[thread] = e.when
				continue
			}
			if e.when.Before(thread.start) || e.when.After(thread.end) {
				colData = append(colData, "")
			} else {
				colData = append(colData, fmt.Sprintf("│ ... %s ...", formatDuration(e.when.Sub(lastTimestamp))))
			}
		}
		for i := 0; i < len(colData); i++ {
			if colWidth := utf8.RuneCountInString(colData[i]); colWidth > colWidths[i] {
				colWidths[i] = colWidth
			}
		}
		rows[i] = colData
	}
	log.Infof("---- %s timing information ----", t.root.name)
	var sb strings.Builder
	for i, row := range rows {
		for j, cell := range row {
			// Check if the rest of the row is empty, and if so, break.
			emptyRest := true
			for k := j; k < len(row); k++ {
				if row[k] != "" {
					emptyRest = false
					break
				}
			}
			if emptyRest {
				break
			}
			// Process cell.
			switch j {
			case 0: // Timestamp column.
				sb.WriteRune('[')
				for s := utf8.RuneCountInString(cell); s < colWidths[j]; s++ {
					sb.WriteRune(' ')
				}
				sb.WriteString(cell)
				sb.WriteRune(']')
			case 1: // Delta column.
				sb.WriteString("  ")
				for s := utf8.RuneCountInString(cell); s < colWidths[j]; s++ {
					sb.WriteRune(' ')
				}
				sb.WriteString(cell)
			case 2: // Delta bar chart column.
				sb.WriteRune(' ') // Only one space of width from first column since it is reflecting the same quantity.
				sb.WriteString(cell)
				for s := utf8.RuneCountInString(cell); s < colWidths[j]; s++ {
					sb.WriteRune(' ')
				}
			default:
				// Other columns.
				sb.WriteString("  ")
				sb.WriteString(cell)
				if j < len(rows[i])-1 {
					for s := utf8.RuneCountInString(cell); s < colWidths[j]; s++ {
						sb.WriteRune(' ')
					}
				}
			}
		}
		log.Infof("%s", sb.String())
		sb.Reset()
	}
	log.Infof("---- End of %s timing information ----", t.root.name)

	// In debug mode, also log a flat list of events that can be easily machine-parsed.
	if log.IsLogging(log.Debug) {
		for _, e := range events {
			switch e.point.pointType {
			case pointTypeStart:
				log.Debugf("%s timing data: %d %s start %s", t.root.name, e.when.UnixNano(), e.when.Format("15:04:05.000000000"), e.point.thread.name)
			case pointTypeMid:
				log.Debugf("%s timing data: %d %s mid %s = %s", t.root.name, e.when.UnixNano(), e.when.Format("15:04:05.000000000"), e.point.thread.name, e.point.midpointName)
			case pointTypeEnd:
				log.Debugf("%s timing data: %d %s end %s", t.root.name, e.when.UnixNano(), e.when.Format("15:04:05.000000000"), e.point.thread.name)
			}
		}
	}
}

// barChart returns a string of width characters that represents the given
// fraction of the given width.
func barChart(fraction float64, width int) string {
	const chars = " ▏▎▍▌▋▊█▉"
	numChars := utf8.RuneCountInString(chars)
	pivotIndex := int(fraction * float64(width))
	pivotRuneIndex := max(0, min(numChars-1, int((fraction-(float64(pivotIndex)/float64(width)))*float64(width*numChars))))
	runes := make([]rune, width)
	for i := 0; i < width; i++ {
		if i < pivotIndex {
			runes[i] = []rune(chars)[numChars-1]
		} else if i == pivotIndex {
			runes[i] = []rune(chars)[pivotRuneIndex]
		} else {
			runes[i] = []rune(chars)[0]
		}
	}
	return string(runes)
}
