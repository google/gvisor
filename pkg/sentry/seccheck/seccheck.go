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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

// A Point represents a checkpoint, a point at which a security check occurs.
type Point uint

const (
	totalPoints            = int(pointLengthBeforeSyscalls) + syscallPoints
	numPointBitmaskUint32s = (totalPoints-1)/32 + 1
)

type FieldSet struct {
	Local   FieldMask
	Context FieldMask
}

type Field uint64

type FieldMask struct {
	mask Field
}

func MakeFieldMask(fields ...Field) FieldMask {
	var m FieldMask
	for _, field := range fields {
		m.Add(field)
	}
	return m
}

func (fm *FieldMask) Contains(field Field) bool {
	return fm.mask&(Field(1)<<uint(field)) != 0
}

func (fm *FieldMask) Add(field Field) {
	fm.mask |= Field(1) << uint(field)
}

func (fm *FieldMask) Remove(field Field) {
	fm.mask &^= Field(1) << uint(field)
}

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
// superset of fields requested by the Checker's corresponding CheckerReq, but
// may be missing requested fields in some cases (e.g. if the Checker is
// registered concurrently with invocations of checkpoints).
type Checker interface {
	Stop()

	Clone(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error
	Execve(ctx context.Context, fields FieldSet, info *pb.ExecveInfo) error
	ExitNotifyParent(ctx context.Context, fields FieldSet, info *pb.ExitNotifyParentInfo) error

	RawSyscall(context.Context, FieldSet, *pb.Syscall) error
	Syscall(context.Context, FieldSet, SyscallToProto, *pb.Common, SyscallInfo) error

	ContainerStart(context.Context, FieldSet, *pb.Start) error
	TaskExit(context.Context, FieldSet, *pb.TaskExit) error
}

// CheckerDefaults may be embedded by implementations of Checker to obtain
// no-op implementations of Checker methods that may be explicitly overridden.
type CheckerDefaults struct{}

var _ Checker = (*CheckerDefaults)(nil)

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

func (CheckerDefaults) RawSyscall(context.Context, FieldSet, *pb.Syscall) error {
	return nil
}

func (CheckerDefaults) Syscall(context.Context, FieldSet, SyscallToProto, *pb.Common, SyscallInfo) error {
	return nil
}

func (CheckerDefaults) ContainerStart(context.Context, FieldSet, *pb.Start) error {
	return nil
}

func (CheckerDefaults) TaskExit(context.Context, FieldSet, *pb.TaskExit) error {
	return nil
}

// PointReq indicates what checkpoint a corresponding Checker runs at, and
// what information it requires at those checkpoints.
type PointReq struct {
	Pt     Point
	Fields FieldSet
}

type CheckerReq struct {
	Points []Point
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
	// enabledPoints is accessed using atomic memory operations. Mutation of
	// enabledPoints is serialized by registrationMu.
	enabledPoints [numPointBitmaskUint32s]uint32

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
		p := req.Pt
		word, bit := p/32, p%32
		atomic.StoreUint32(&s.enabledPoints[word], s.enabledPoints[word]|(uint32(1)<<bit))

		s.pointFields[p] = req.Fields
	}
}

func (s *State) clearCheckers() {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	for i := range s.enabledPoints {
		atomic.StoreUint32(&s.enabledPoints[i], 0)
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
	return atomic.LoadUint32(&s.enabledPoints[word])&(uint32(1)<<bit) != 0
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

func (s *State) SendToCheckers(fn func(c Checker) error) error {
	for _, c := range s.getCheckers() {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

func (s *State) GetFieldSet(p Point) FieldSet {
	s.registrationMu.RLock()
	defer s.registrationMu.RUnlock()
	return s.pointFields[p]
}
