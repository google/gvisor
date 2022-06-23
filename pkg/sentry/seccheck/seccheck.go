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
	numPointBitmaskUint32s = (totalPoints-1)/32 + 1
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

// A Checker performs security checks at checkpoints.
//
// Each Checker method X is called at checkpoint X; if the method may return a
// non-nil error and does so, it causes the checked operation to fail
// immediately (without calling subsequent Checkers) and return the error. The
// info argument contains information relevant to the check. The mask argument
// indicates what fields in info are valid; the mask should usually be a
// superset of fields requested by the Checker's corresponding PointReq, but
// may be missing requested fields in some cases (e.g. if the Checker is
// registered concurrently with invocations of checkpoints).
type Checker interface {
	// Name return the checker name.
	Name() string
	// Status returns the checker runtime status.
	Status() CheckerStatus
	// Stop requests the checker to stop.
	Stop()

	Clone(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error
	Execve(ctx context.Context, fields FieldSet, info *pb.ExecveInfo) error
	ExitNotifyParent(ctx context.Context, fields FieldSet, info *pb.ExitNotifyParentInfo) error
	TaskExit(context.Context, FieldSet, *pb.TaskExit) error

	ContainerStart(context.Context, FieldSet, *pb.Start) error

	Syscall(context.Context, FieldSet, *pb.ContextData, pb.MessageType, proto.Message) error
	RawSyscall(context.Context, FieldSet, *pb.Syscall) error
}

// CheckerStatus represents stats about each checker instance.
type CheckerStatus struct {
	// DroppedCount is the number of trace points dropped.
	DroppedCount uint64
}

// CheckerDefaults may be embedded by implementations of Checker to obtain
// no-op implementations of Checker methods that may be explicitly overridden.
type CheckerDefaults struct{}

// Add functions missing in CheckerDefaults to make it possible to check for the
// implementation below to catch missing functions more easily.
type checkerDefaultsImpl struct {
	CheckerDefaults
}

// Name implements Checker.Name.
func (checkerDefaultsImpl) Name() string { return "" }

var _ Checker = (*checkerDefaultsImpl)(nil)

// Status implements Checker.Status.
func (CheckerDefaults) Status() CheckerStatus {
	return CheckerStatus{}
}

// Stop implements Checker.Stop.
func (CheckerDefaults) Stop() {}

// Clone implements Checker.Clone.
func (CheckerDefaults) Clone(context.Context, FieldSet, *pb.CloneInfo) error {
	return nil
}

// Execve implements Checker.Execve.
func (CheckerDefaults) Execve(context.Context, FieldSet, *pb.ExecveInfo) error {
	return nil
}

// ExitNotifyParent implements Checker.ExitNotifyParent.
func (CheckerDefaults) ExitNotifyParent(context.Context, FieldSet, *pb.ExitNotifyParentInfo) error {
	return nil
}

// ContainerStart implements Checker.ContainerStart.
func (CheckerDefaults) ContainerStart(context.Context, FieldSet, *pb.Start) error {
	return nil
}

// TaskExit implements Checker.TaskExit.
func (CheckerDefaults) TaskExit(context.Context, FieldSet, *pb.TaskExit) error {
	return nil
}

// RawSyscall implements Checker.RawSyscall.
func (CheckerDefaults) RawSyscall(context.Context, FieldSet, *pb.Syscall) error {
	return nil
}

// Syscall implements Checker.Syscall.
func (CheckerDefaults) Syscall(context.Context, FieldSet, *pb.ContextData, pb.MessageType, proto.Message) error {
	return nil
}

// PointReq indicates what Point a corresponding Checker runs at, and what
// information it requires at those Points.
type PointReq struct {
	Pt     Point
	Fields FieldSet
}

// Global is the method receiver of all seccheck functions.
var Global State

// State is the type of global, and is separated out for testing.
type State struct {
	// registrationMu serializes all changes to the set of registered Checkers
	// for all checkpoints.
	registrationMu sync.RWMutex

	// enabledPoints is a bitmask of checkpoints for which at least one Checker
	// is registered.
	//
	// Mutation of enabledPoints is serialized by registrationMu.
	enabledPoints [numPointBitmaskUint32s]atomicbitops.Uint32

	// registrationSeq supports store-free atomic reads of registeredCheckers.
	registrationSeq sync.SeqCount

	// checkers is the set of all registered Checkers in order of execution.
	//
	// checkers is accessed using instantiations of SeqAtomic functions.
	// Mutation of checkers is serialized by registrationMu.
	checkers []Checker

	pointFields map[Point]FieldSet
}

// AppendChecker registers the given Checker to execute at checkpoints. The
// Checker will execute after all previously-registered Checkers, and only if
// those Checkers return a nil error.
func (s *State) AppendChecker(c Checker, reqs []PointReq) {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	s.appendCheckerLocked(c)
	if s.pointFields == nil {
		s.pointFields = make(map[Point]FieldSet)
	}
	for _, req := range reqs {
		word, bit := req.Pt/32, req.Pt%32
		s.enabledPoints[word].Store(s.enabledPoints[word].RacyLoad() | (uint32(1) << bit))

		s.pointFields[req.Pt] = req.Fields
	}
}

func (s *State) clearCheckers() {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	for i := range s.enabledPoints {
		s.enabledPoints[i].Store(0)
	}
	s.pointFields = nil

	oldCheckers := s.getCheckers()
	s.registrationSeq.BeginWrite()
	s.checkers = nil
	s.registrationSeq.EndWrite()
	for _, checker := range oldCheckers {
		checker.Stop()
	}
}

// Enabled returns true if any Checker is registered for the given checkpoint.
func (s *State) Enabled(p Point) bool {
	word, bit := p/32, p%32
	if int(word) >= len(s.enabledPoints) {
		return false
	}
	return s.enabledPoints[word].Load()&(uint32(1)<<bit) != 0
}

func (s *State) getCheckers() []Checker {
	return SeqAtomicLoadCheckerSlice(&s.registrationSeq, &s.checkers)
}

// Preconditions: s.registrationMu must be locked.
func (s *State) appendCheckerLocked(c Checker) {
	s.registrationSeq.BeginWrite()
	s.checkers = append(s.checkers, c)
	s.registrationSeq.EndWrite()
}

// SendToCheckers iterates over all checkers and calls fn for each one of them.
func (s *State) SendToCheckers(fn func(c Checker) error) error {
	for _, c := range s.getCheckers() {
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
