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

package seccheck

import (
	"errors"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

type testChecker struct {
	CheckerDefaults

	onClone func(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error
}

// Clone implements Checker.Clone.
func (c *testChecker) Clone(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error {
	if c.onClone == nil {
		return nil
	}
	return c.onClone(ctx, fields, info)
}

func TestNoChecker(t *testing.T) {
	var s State
	if s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got true, wanted false")
	}
}

func TestCheckerNotRegisteredForPoint(t *testing.T) {
	var s State
	s.AppendChecker(&testChecker{}, nil)
	if s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got true, wanted false")
	}
}

func TestCheckerRegistered(t *testing.T) {
	var s State
	checkerCalled := false
	checker := &testChecker{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			checkerCalled = true
			return nil
		},
	}
	req := []PointReq{
		{
			Pt:     PointClone,
			Fields: FieldSet{Context: MakeFieldMask(FieldCommonCredentials)},
		},
	}
	s.AppendChecker(checker, req)

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	fields := s.GetFieldSet(PointClone)
	if !fields.Context.Contains(FieldCommonCredentials) {
		t.Errorf("fields.Context.Contains(PointContextCredentials): got false, wanted true")
	}
	if err := s.Clone(context.Background(), fields, &pb.CloneInfo{}); err != nil {
		t.Errorf("Clone(): got %v, wanted nil", err)
	}
	if !checkerCalled {
		t.Errorf("Clone() did not call Checker.Clone()")
	}
}

func TestMultipleCheckersRegistered(t *testing.T) {
	var s State
	checkersCalled := [2]bool{}
	checker := &testChecker{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			checkersCalled[0] = true
			return nil
		},
	}
	reqs := []PointReq{
		{Pt: PointClone},
	}
	s.AppendChecker(checker, reqs)

	checker = &testChecker{onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
		checkersCalled[1] = true
		return nil
	}}
	reqs = []PointReq{
		{Pt: PointClone},
	}
	s.AppendChecker(checker, reqs)

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	// CloneReq() should return the union of requested fields from all calls to
	// AppendChecker.
	fields := s.GetFieldSet(PointClone)
	if err := s.Clone(context.Background(), fields, &pb.CloneInfo{}); err != nil {
		t.Errorf("Clone(): got %v, wanted nil", err)
	}
	for i := range checkersCalled {
		if !checkersCalled[i] {
			t.Errorf("Clone() did not call Checker.Clone() index %d", i)
		}
	}
}

func TestCheckpointReturnsFirstCheckerError(t *testing.T) {
	errFirstChecker := errors.New("first Checker error")
	errSecondChecker := errors.New("second Checker error")

	var s State
	checkersCalled := [2]bool{}
	checker := &testChecker{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			checkersCalled[0] = true
			return errFirstChecker
		},
	}
	reqs := []PointReq{
		{Pt: PointClone},
	}

	s.AppendChecker(checker, reqs)

	checker = &testChecker{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			checkersCalled[1] = true
			return errSecondChecker
		},
	}
	s.AppendChecker(checker, reqs)

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	if err := s.Clone(context.Background(), FieldSet{}, &pb.CloneInfo{}); err != errFirstChecker {
		t.Errorf("Clone(): got %v, wanted %v", err, errFirstChecker)
	}
	if !checkersCalled[0] {
		t.Errorf("Clone() did not call first Checker")
	}
	if checkersCalled[1] {
		t.Errorf("Clone() called second Checker")
	}
}
