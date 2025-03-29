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

const (
	// fullTimestampFormat is the format string for a timestamp with nanosecond
	// precision but no date component.
	fullTimestampFormat = "15:04:05.000000000"

	// microsTimestampFormat is the format string for a timestamp with
	// microsecond precision but no date component.
	microsTimestampFormat = "15:04:05.000000"
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
// time until it ends (i.e. its endpoint becomes defined), at which point
// ownership transfers to the goroutine that owns the Timer that created it.
//
// A Timeline may be nil, in which case all methods are no-ops. This means all
// code that takes in a Timeline parameter does not need to check for nilness.
type Timeline struct {
	// name is the name of the Timeline.
	name string

	// fullName is the fully-qualified name of this Timeline, including the
	// names of its ancestors.
	fullName string

	// timer is the Timer that owns this Timeline.
	// This is nil on orphaned Timelines.
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
	s.ReachedAt(name, time.Now())
}

// ReachedAt records a new midpoint on the root Timeline of the Timer with
// the given timestamp.
func (s *Timeline) ReachedAt(name string, when time.Time) {
	if s == nil {
		return
	}
	s.midpoints = append(s.midpoints, MidPoint{
		when: when,
		name: name,
	})
	if log.IsLogging(log.Debug) {
		if s.timer != nil {
			log.Debugf("Timer for %s: Timeline %s reached midpoint %s at %s (unix nanos: %d)", s.timer.root.name, s.fullName, name, when.Format(fullTimestampFormat), when.UnixNano())
		} else {
			log.Debugf("Orphaned timeline %s reached midpoint %s at %s (unix nanos: %d)", s.name, name, when.Format(fullTimestampFormat), when.UnixNano())
		}
	}
}

// Fork creates a new Timeline that is a child of this one.
// A midpoint is implicitly added to the current Timeline.
//
// The returned Timeline is initially owned by the caller, but may be passed
// to another goroutine if desired.
//
// A child timeline may but does not need to end before the parent does.
//
// Forked timelines are useful to represent parallel operations like separate
// goroutines, and are actually required in such cases so that the goroutine
// can own its own Timeline, but non-concurrent code may also use Fork to
// represent its own linear operations as a tree if it so desires.
func (s *Timeline) Fork(name string) *Timeline {
	if s == nil {
		return nil
	}
	now := time.Now()
	if s.timer == nil {
		panic("timing.Timeline.Fork called on Timeline that has no parent; must call Timer.Adopt first")
	}
	s.timer.runningTimelines.Add(1)
	sub := &Timeline{
		name:     name,
		fullName: fmt.Sprintf("%s/%s", s.fullName, name),
		timer:    s.timer,
		start:    now,
	}
	s.children = append(s.children, sub)
	s.midpoints = append(s.midpoints, MidPoint{
		when: now,
		name: "forked",
	})
	// Check for log level here to avoid allocating a string to format the
	// timestamp if it is not going to be logged.
	if log.IsLogging(log.Debug) {
		log.Debugf("Timer for %s: Timeline %s forked into child timeline %s at %s (unix nanos: %d)", s.timer.root.name, s.fullName, sub.fullName, now.Format(fullTimestampFormat), now.UnixNano())
	}
	return sub
}

// MultiFork creates new Timelines that are children of this one.
// It returns as many Timelines as there are names in `names`.
// All of them share the same start time.
// A midpoint is implicitly added to the current Timeline.
// The same semantics as `Timeline.Fork` apply.
func (s *Timeline) MultiFork(names []string) []*Timeline {
	if len(names) == 0 {
		return nil
	}
	if s == nil {
		return make([]*Timeline, len(names))
	}
	now := time.Now()
	if s.timer == nil {
		panic("timing.Timeline.MultiFork called on Timeline that has no parent; must call Timer.Adopt first")
	}
	s.timer.runningTimelines.Add(int64(len(names)))
	children := make([]*Timeline, len(names))
	for i, name := range names {
		children[i] = &Timeline{
			name:     name,
			fullName: fmt.Sprintf("%s/%s", s.fullName, name),
			timer:    s.timer,
			start:    now,
		}
	}
	s.children = append(s.children, children...)
	s.midpoints = append(s.midpoints, MidPoint{
		when: now,
		name: "forked",
	})
	// Check for log level here to avoid allocating a string to format the
	// timestamp if it is not going to be logged.
	if log.IsLogging(log.Debug) {
		log.Debugf("Timer for %s: Timeline %s forked %d-way into child timelines %v at %s (unix nanos: %d)", s.timer.root.name, s.fullName, len(names), names, now.Format(fullTimestampFormat), now.UnixNano())
	}
	return children
}

// traverse visits all Timelines in the tree rooted at s.
// fn is called exactly once per Timeline as the `child` argument.
// The root Timeline has a `nil` parent.
func (s *Timeline) traverse(parent *Timeline, fn func(parent, child *Timeline)) {
	if s == nil {
		return
	}
	fn(parent, s)
	for _, child := range s.children {
		child.traverse(s, fn)
	}
}

// End marks the Timeline as having ended. It must be eventually called on all
// Timelines.
// After End is called, the ownership of the Timeline struct moves to the
// goroutine that owns the Timer that created it.
func (s *Timeline) End() {
	if s == nil {
		return
	}
	end := time.Now()
	if s.timer == nil {
		log.Debugf("Orphaned timeline %s ended without having been adopted. This is possibly unintended.", s.name)
		return
	}
	if !s.end.IsZero() {
		log.Debugf("Timer for %s: Timeline %s ended twice. This is possibly unintended.", s.timer.root.name, s.fullName)
		return
	}
	s.end = end
	s.timer.runningTimelines.Add(-1)
	// Check for log level here to avoid allocating a string to format the
	// timestamp if it is not going to be logged.
	if log.IsLogging(log.Debug) {
		log.Debugf("Timer for %s: Timeline %s ended at %s (unix nanos: %d)", s.timer.root.name, s.fullName, s.end.Format(fullTimestampFormat), s.end.UnixNano())
	}
}

// A Lease is a reference to a Timeline that is valid until the Lease is
// canceled. After calling Lease on a Timeline, the caller should no longer
// use the Timeline directly, and should instead use the Lease exclusively.
//
// Leases should typically not cross function boundaries.
//
// Leases are useful in complex functions where ownership of a Timeline
// needs to be *conditionally transferred* to a different goroutine at some
// late point in the function. Consider this example:
//
// ```
//
//	func SomeLongFunction(timeline *timing.Timeline) {
//	  defer timeline.End() // Convenient to defer `End` to hit all the `return` branches.
//	  timeline.Reached("some_point")
//
//	  if err := something(timeline); err != nil {
//	    return
//	  }
//	  timeline.Reached("some_other_point")
//	  if err := somethingElse(); err != nil {
//	    timeline.Reached("some_error")
//	    return
//	  }
//	  timeline.Reached("another_point")
//	  go doSomethingElse(timeline)
//
//	  // Don't want to call `End` anymore here!
//	}
//
// ```
//
// With a Lease:
//
// ```
//
//	func SomeLongFunction(timeline *timing.Timeline) {
//	  lease := timeline.Lease()
//	  defer lease.End()
//	  lease.Reached("some_point")
//
//	  if err := something(); err != nil {
//	    lease.Reached("some_error")
//	    return
//	  }
//	  if err := somethingElse(); err != nil {
//	    lease.Reached("some_other_error")
//	    return
//	  }
//	  lease.Reached("another_point")
//	  go doSomethingElse(lease.Transfer())
//
//	  // `End` is not called anymore here.
//	}
//
// ```
type Lease struct {
	timeline *Timeline
	valid    bool
}

// Reached records a new midpoint on the Timeline if the Lease is valid.
// See `Timeline.Reached` for more details.
func (l *Lease) Reached(name string) {
	if l == nil || !l.valid {
		return
	}
	l.timeline.Reached(name)
}

// Fork forks the Timeline if the Lease is valid.
// See `Timeline.Fork` for more details.
func (l *Lease) Fork(name string) *Timeline {
	if l == nil || !l.valid {
		return nil
	}
	return l.timeline.Fork(name)
}

// MultiFork forks the Timeline if the Lease is valid.
// See `Timeline.MultiFork` for more details.
func (l *Lease) MultiFork(names []string) []*Timeline {
	if l == nil || !l.valid {
		return nil
	}
	return l.timeline.MultiFork(names)
}

// End ends the Timeline if the Lease is valid.
// See `Timeline.End` for more details.
func (l *Lease) End() {
	if l == nil || !l.valid {
		return
	}
	l.valid = false
	l.timeline.End()
}

// Transfer invalidates the current Lease and returns the underlying Timeline.
// Typically useful when transferring ownership of a Timeline to a different
// goroutine while giving up ownership in the current one.
// See `Lease` documentation for example usage.
func (l *Lease) Transfer() *Timeline {
	if l == nil {
		return nil
	}
	if !l.valid {
		panic("timing.Lease.Transfer called on invalid Lease")
	}
	l.valid = false
	return l.timeline
}

// Lease returns a Lease for the Timeline.
// The Lease is valid until it is canceled by calling `End` or `Transfer`.
// See `Lease` for example usage.
func (s *Timeline) Lease() *Lease {
	if s == nil {
		return nil
	}
	return &Lease{
		timeline: s,
		valid:    true,
	}
}

// OrphanTimeline creates a new Timeline that is not owned by any Timer.
// This is useful for operations that are meant to be later reparented to a
// parent Timer, but where timing measurements are desired before the parent
// Timer is known.
// The returned Timeline must be parented with `SetParent` in order to be
// useful.
func OrphanTimeline(name string, startTime time.Time) *Timeline {
	// Check for log level here to avoid allocating a string to format the
	// timestamp if it is not going to be logged.
	if log.IsLogging(log.Debug) {
		log.Debugf("Orphaned timeline %s started at %s (unix nanos: %d)", name, startTime.Format(fullTimestampFormat), startTime.UnixNano())
	}
	return &Timeline{
		name:     name,
		fullName: "_ORPHANED_",
		start:    startTime,
	}
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

	// runningTimelines is the number of Timelines that have not yet ended.
	// When dumping timing data, this is used to wait for all Timelines to end.
	runningTimelines atomicbitops.Int64
}

// New creates a new Timer.
// The given name is used to identify the Timer in pretty-printed output.
// The given startTime is used as the start time of the Timer's root Timeline.
func New(name string, startTime time.Time) *Timer {
	log.Infof("Timer for %s: Starting.", name)
	timer := &Timer{}
	timer.runningTimelines.Store(1)
	root := &Timeline{
		name:     name,
		fullName: name,
		timer:    timer,
		start:    startTime,
	}
	timer.root = root
	return timer
}

// StartTime returns the start time of the Timer.
func (t *Timer) StartTime() time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.root.start
}

// Reached records a new midpoint on the root Timeline of the Timer.
func (t *Timer) Reached(name string) {
	if t == nil {
		return
	}
	t.root.Reached(name)
}

// ReachedAt records a new midpoint on the root Timeline of the Timer with
// the given timestamp.
func (t *Timer) ReachedAt(name string, when time.Time) {
	if t == nil {
		return
	}
	t.root.ReachedAt(name, when)
}

// Fork creates a new Timeline that is a child of the root Timeline of this
// Timer.
// The returned Timeline is initially owned by the caller, but may be passed
// to another goroutine if desired.
// This child Timeline may but does not need to end before the root timeline
// does.
// Forked timelines are useful to represent parallel operations like separate
// goroutines, and are actually required in such cases so that the goroutine
// can own its own Timeline, but non-concurrent code may also use Fork to
// represent its own linear operations as a tree if it so desires.
func (t *Timer) Fork(name string) *Timeline {
	if t == nil {
		return nil
	}
	return t.root.Fork(name)
}

// MultiFork creates new Timelines that are children of the root Timeline of
// this Timer.
// See Timeline.MultiFork for more details.
func (t *Timer) MultiFork(names []string) []*Timeline {
	if len(names) == 0 {
		return nil
	}
	if t == nil {
		return make([]*Timeline, len(names))
	}
	return t.root.MultiFork(names)
}

// Adopt adopts a Timeline into this Timer.
// May only be called with Timelines created by `OrphanTimeline`,
// and may only be called once per such Timeline.
// The calling goroutine must own both the Timeline and the Timer.
func (t *Timer) Adopt(child *Timeline) {
	if t == nil || child == nil {
		return
	}
	if child.timer != nil {
		panic("timing.Timeline.Adopt called on Timeline that already has a parent")
	}
	t.root.children = append(t.root.children, child)
	if child.end.IsZero() {
		t.runningTimelines.Add(1)
	}
	child.timer = t
	child.fullName = fmt.Sprintf("%s/%s", t.root.fullName, child.name)
	log.Debugf("Timer for %s: Timeline %s adopted.", t.root.name, child.fullName)
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
	var hadChildTimelines int64
	if t.root.end.IsZero() {
		t.root.End()
		if hadChildTimelines = t.runningTimelines.Load(); hadChildTimelines > 0 {
			log.Infof("Timer for %s: Root timeline ended, but %d child timelines are still running...", t.root.name, hadChildTimelines)
		} else {
			log.Infof("Timer for %s: Ended.", t.root.name)
		}
	}
	const (
		stillWaitingLogThreshold = 10 * time.Second
		stillWaitingLogInterval  = 1 * time.Second
	)
	startedWaiting := time.Now()
	var rlLogger log.Logger
	for runningTimelines := t.runningTimelines.Load(); runningTimelines != 0; runningTimelines = t.runningTimelines.Load() {
		if runningTimelines < 0 {
			panic("timing.Timeline.End called too many times in aggregate")
		}
		time.Sleep(1 * time.Millisecond)
		if rlLogger == nil && time.Since(startedWaiting) > stillWaitingLogThreshold {
			rlLogger = log.BasicRateLimitedLogger(stillWaitingLogInterval)
		}
		if rlLogger != nil {
			if log.IsLogging(log.Debug) {
				// UNSAFE code to traverse the tree and print out all timelines that
				// are still running. Only executed in debug-logging mode.
				var timelineNames []string
				t.root.traverse(nil, func(_, child *Timeline) {
					if child.end.IsZero() {
						timelineNames = append(timelineNames, child.fullName)
					}
				})
				rlLogger.Debugf("Timer for %s: Still waiting for %d child timelines to finish: %v", t.root.name, runningTimelines, timelineNames)
				// Sleep longer in debug mode to make sure we don't do the above traversal every millisecond.
				time.Sleep(100 * time.Millisecond)
			} else {
				rlLogger.Infof("Timer for %s: Still waiting for %d child timelines to finish...", t.root.name, runningTimelines)
			}
		}
	}
	if hadChildTimelines > 0 {
		log.Infof("Timer for %s: All child timelines have ended.", t.root.name)
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
		timeline     *Timeline
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
				return fmt.Sprintf("%d %03dµs", us/1000, us%1000)
			}
			return fmt.Sprintf("%dµs", us)
		case totalDuration < 3*time.Minute:
			return fmt.Sprintf("%.3fs", float64(d.Milliseconds())/1000)
		default:
			return d.Truncate(time.Second).String()
		}
	}
	var flatTimelines []*Timeline
	t.root.traverse(nil, func(_, child *Timeline) {
		flatTimelines = append(flatTimelines, child)
	})
	var events []event
	for _, timeline := range flatTimelines {
		events = append(events, event{when: timeline.start, point: point{timeline: timeline, pointType: pointTypeStart}})
		for _, mid := range timeline.midpoints {
			events = append(events, event{when: mid.when, point: point{timeline: timeline, pointType: pointTypeMid, midpointName: mid.name}})
		}
		events = append(events, event{when: timeline.end, point: point{timeline: timeline, pointType: pointTypeEnd}})
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
		if interval := dedupEvents[i].when.Sub(dedupEvents[i-1].when); interval > largestInterval {
			largestInterval = interval
		}
	}

	rows := make([][]string, len(dedupEvents))
	colWidths := make([]int, len(flatTimelines)+3)
	lastTimestampPerTimeline := make(map[*Timeline]time.Time)
	for i, e := range dedupEvents {
		colData := make([]string, 0, len(flatTimelines)+3)
		colData = append(colData, e.when.Format(microsTimestampFormat))
		if i == 0 {
			colData = append(colData, "")
			colData = append(colData, "")
		} else {
			sincePrevious := e.when.Sub(dedupEvents[i-1].when)
			colData = append(colData, fmt.Sprintf("+%s", formatDuration(sincePrevious)))
			colData = append(colData, barChart(float64(sincePrevious)/float64(largestInterval), 12))
		}
		for _, timeline := range flatTimelines {
			lastTimestamp, ok := lastTimestampPerTimeline[timeline]
			if !ok {
				lastTimestamp = timeline.start
			}
			timelineChanged := false
			for _, p := range e.points {
				if p.timeline == timeline {
					switch p.pointType {
					case pointTypeStart:
						colData = append(colData, fmt.Sprintf("╭─ %s", timeline.name))
					case pointTypeMid:
						colData = append(colData, fmt.Sprintf("├─ %s: %s", p.midpointName, formatDuration(e.when.Sub(lastTimestamp))))
					case pointTypeEnd:
						colData = append(colData, fmt.Sprintf("╰─ END: %s", formatDuration(timeline.end.Sub(lastTimestamp))))
					}
					timelineChanged = true
					break
				}
			}
			if timelineChanged {
				lastTimestampPerTimeline[timeline] = e.when
				continue
			}
			if e.when.Before(timeline.start) || e.when.After(timeline.end) {
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
	var sb strings.Builder
	sb.WriteString("---- ")
	sb.WriteString(t.root.name)
	sb.WriteString(" timing information ----\n")
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
				sb.WriteRune('\t')
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
				sb.WriteRune('\t')
				sb.WriteString(cell)
				if j < len(rows[i])-1 {
					for s := utf8.RuneCountInString(cell); s < colWidths[j]; s++ {
						sb.WriteRune(' ')
					}
				}
			}
		}
		sb.WriteRune('\n')
	}
	sb.WriteString("---- End of ")
	sb.WriteString(t.root.name)
	sb.WriteString(" timing information ----\n")
	log.Infof("%s", sb.String())

	// In debug mode, also log a flat list of events that can be easily machine-parsed.
	if log.IsLogging(log.Debug) {
		for _, e := range events {
			switch e.point.pointType {
			case pointTypeStart:
				log.Debugf("Timer for %s: time %d %s start %s", t.root.name, e.when.UnixNano(), e.when.Format(fullTimestampFormat), e.point.timeline.fullName)
			case pointTypeMid:
				log.Debugf("Timer for %s: time %d %s mid %s = %s", t.root.name, e.when.UnixNano(), e.when.Format(fullTimestampFormat), e.point.timeline.fullName, e.point.midpointName)
			case pointTypeEnd:
				log.Debugf("Timer for %s: time %d %s end %s", t.root.name, e.when.UnixNano(), e.when.Format(fullTimestampFormat), e.point.timeline.fullName)
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
