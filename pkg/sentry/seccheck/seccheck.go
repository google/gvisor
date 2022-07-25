// Copyright 2021 The gVisor Authors.
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

// Package seccheck defines a structure for dynamically-configured security
// checks in the sentry.
package seccheck

import (
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

// A Point represents a checkpoint, a point at which a security check occurs.
type Point uint

// PointX represents the checkpoint X.
const (
	totalPoints            = int(pointLengthBeforeSyscalls) + syscallPoints
	numPointsPerUint32     = 32
	numPointBitmaskUint32s = (totalPoints-1)/numPointsPerUint32 + 1
)

// FieldSet contains all optional fields to be collected by a given Point.
type FieldSet struct {
	// Local indicates which optional fields from the Point that needs to be
	// collected, e.g. resolving path from an FD, or collecting a large field.
	Local FieldMask

	// Context indicates which optional fields from the Context that needs to be
	// collected, e.g. PID, credentials, current time.
	Context FieldMask
}

// Field represents the index of a single optional field to be collect for a
// Point.
type Field uint

// FieldMask is a bitmask with a single bit representing an optional field to be
// collected. The meaning of each bit varies per point. The mask is currently
// limited to 64 fields. If more are needed, FieldMask can be expanded to
// support additional fields.
type FieldMask struct {
	mask uint64
}

// MakeFieldMask creates a FieldMask from a set of Fields.
func MakeFieldMask(fields ...Field) FieldMask {
	var m FieldMask
	for _, field := range fields {
		m.Add(field)
	}
	return m
}

// Contains returns true if the mask contains the Field.
func (fm *FieldMask) Contains(field Field) bool {
	return fm.mask&(1<<field) != 0
}

// Add adds a Field to the mask.
func (fm *FieldMask) Add(field Field) {
	fm.mask |= 1 << field
}

// Remove removes a Field from the mask.
func (fm *FieldMask) Remove(field Field) {
	fm.mask &^= 1 << field
}

// Empty returns true if no bits are set.
func (fm *FieldMask) Empty() bool {
	return fm.mask == 0
}

// A Sink performs security checks at checkpoints.
//
// Each Sink method X is called at checkpoint X; if the method may return a
// non-nil error and does so, it causes the checked operation to fail
// immediately (without calling subsequent Sinks) and return the error. The
// info argument contains information relevant to the check. The mask argument
// indicates what fields in info are valid; the mask should usually be a
// superset of fields requested by the Sink's corresponding PointReq, but
// may be missing requested fields in some cases (e.g. if the Sink is
// registered concurrently with invocations of checkpoints).
type Sink interface {
	// Name return the sink name.
	Name() string
	// Status returns the sink runtime status.
	Status() SinkStatus
	// Stop requests the sink to stop.
	Stop()

	Clone(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error
	Execve(ctx context.Context, fields FieldSet, info *pb.ExecveInfo) error
	ExitNotifyParent(ctx context.Context, fields FieldSet, info *pb.ExitNotifyParentInfo) error
	TaskExit(context.Context, FieldSet, *pb.TaskExit) error

	ContainerStart(context.Context, FieldSet, *pb.Start) error

	Syscall(context.Context, FieldSet, *pb.ContextData, pb.MessageType, proto.Message) error
	RawSyscall(context.Context, FieldSet, *pb.Syscall) error
}

// SinkStatus represents stats about each Sink instance.
type SinkStatus struct {
	// DroppedCount is the number of trace points dropped.
	DroppedCount uint64
}

// SinkDefaults may be embedded by implementations of Sink to obtain
// no-op implementations of Sink methods that may be explicitly overridden.
type SinkDefaults struct{}

// Add functions missing in SinkDefaults to make it possible to check for the
// implementation below to catch missing functions more easily.
type sinkDefaultsImpl struct {
	SinkDefaults
}

// Name implements Sink.Name.
func (sinkDefaultsImpl) Name() string { return "" }

var _ Sink = (*sinkDefaultsImpl)(nil)

// Status implements Sink.Status.
func (SinkDefaults) Status() SinkStatus {
	return SinkStatus{}
}

// Stop implements Sink.Stop.
func (SinkDefaults) Stop() {}

// Clone implements Sink.Clone.
func (SinkDefaults) Clone(context.Context, FieldSet, *pb.CloneInfo) error {
	return nil
}

// Execve implements Sink.Execve.
func (SinkDefaults) Execve(context.Context, FieldSet, *pb.ExecveInfo) error {
	return nil
}

// ExitNotifyParent implements Sink.ExitNotifyParent.
func (SinkDefaults) ExitNotifyParent(context.Context, FieldSet, *pb.ExitNotifyParentInfo) error {
	return nil
}

// ContainerStart implements Sink.ContainerStart.
func (SinkDefaults) ContainerStart(context.Context, FieldSet, *pb.Start) error {
	return nil
}

// TaskExit implements Sink.TaskExit.
func (SinkDefaults) TaskExit(context.Context, FieldSet, *pb.TaskExit) error {
	return nil
}

// RawSyscall implements Sink.RawSyscall.
func (SinkDefaults) RawSyscall(context.Context, FieldSet, *pb.Syscall) error {
	return nil
}

// Syscall implements Sink.Syscall.
func (SinkDefaults) Syscall(context.Context, FieldSet, *pb.ContextData, pb.MessageType, proto.Message) error {
	return nil
}

// PointReq indicates what Point a corresponding Sink runs at, and what
// information it requires at those Points.
type PointReq struct {
	Pt     Point
	Fields FieldSet
}

// Global is the method receiver of all seccheck functions.
var Global State

// State is the type of global, and is separated out for testing.
type State struct {
	// registrationMu serializes all changes to the set of registered Sinks
	// for all checkpoints.
	registrationMu sync.RWMutex

	// enabledPoints is a bitmask of checkpoints for which at least one Sink
	// is registered.
	//
	// Mutation of enabledPoints is serialized by registrationMu.
	enabledPoints [numPointBitmaskUint32s]atomicbitops.Uint32

	// registrationSeq supports store-free atomic reads of registeredSinks.
	registrationSeq sync.SeqCount

	// sinks is the set of all registered Sinks in order of execution.
	//
	// sinks is accessed using instantiations of SeqAtomic functions.
	// Mutation of sinks is serialized by registrationMu.
	sinks []Sink

	// syscallFlagListeners is the set of registered SyscallFlagListeners.
	//
	// They are notified when the enablement of a syscall point changes.
	// Mutation of syscallFlagListeners is serialized by registrationMu.
	syscallFlagListeners []SyscallFlagListener

	pointFields map[Point]FieldSet
}

// AppendSink registers the given Sink to execute at checkpoints. The
// Sink will execute after all previously-registered sinks, and only if
// those Sinks return a nil error.
func (s *State) AppendSink(c Sink, reqs []PointReq) {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	s.appendSinkLocked(c)
	if s.pointFields == nil {
		s.pointFields = make(map[Point]FieldSet)
	}
	updateSyscalls := false
	for _, req := range reqs {
		word, bit := req.Pt/numPointsPerUint32, req.Pt%numPointsPerUint32
		s.enabledPoints[word].Store(s.enabledPoints[word].RacyLoad() | (uint32(1) << bit))
		if req.Pt >= pointLengthBeforeSyscalls {
			updateSyscalls = true
		}
		s.pointFields[req.Pt] = req.Fields
	}
	if updateSyscalls {
		for _, listener := range s.syscallFlagListeners {
			listener.UpdateSecCheck(s)
		}
	}
}

func (s *State) clearSink() {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	updateSyscalls := false
	for i := range s.enabledPoints {
		s.enabledPoints[i].Store(0)
		// We use i+1 here because we want to check the last bit that may have been changed within i.
		if Point((i+1)*numPointsPerUint32) >= pointLengthBeforeSyscalls {
			updateSyscalls = true
		}
	}
	if updateSyscalls {
		for _, listener := range s.syscallFlagListeners {
			listener.UpdateSecCheck(s)
		}
	}
	s.pointFields = nil

	oldSinks := s.getSinks()
	s.registrationSeq.BeginWrite()
	s.sinks = nil
	s.registrationSeq.EndWrite()
	for _, sink := range oldSinks {
		sink.Stop()
	}
}

// AddSyscallFlagListener adds a listener to the State.
//
// The listener will be notified whenever syscall point enablement changes.
func (s *State) AddSyscallFlagListener(listener SyscallFlagListener) {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()
	s.syscallFlagListeners = append(s.syscallFlagListeners, listener)
}

// Enabled returns true if any Sink is registered for the given checkpoint.
func (s *State) Enabled(p Point) bool {
	word, bit := p/numPointsPerUint32, p%numPointsPerUint32
	if int(word) >= len(s.enabledPoints) {
		return false
	}
	return s.enabledPoints[word].Load()&(uint32(1)<<bit) != 0
}

func (s *State) getSinks() []Sink {
	return SeqAtomicLoadSinkSlice(&s.registrationSeq, &s.sinks)
}

// Preconditions: s.registrationMu must be locked.
func (s *State) appendSinkLocked(c Sink) {
	s.registrationSeq.BeginWrite()
	s.sinks = append(s.sinks, c)
	s.registrationSeq.EndWrite()
}

// SentToSinks iterates over all sinks and calls fn for each one of them.
func (s *State) SentToSinks(fn func(c Sink) error) error {
	for _, c := range s.getSinks() {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

// GetFieldSet returns the FieldSet that has been configured for a given Point.
func (s *State) GetFieldSet(p Point) FieldSet {
	s.registrationMu.RLock()
	defer s.registrationMu.RUnlock()
	return s.pointFields[p]
}
