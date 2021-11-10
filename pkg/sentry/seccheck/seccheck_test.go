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
)

type testChecker struct {
	CheckerDefaults

	onClone func(ctx context.Context, mask CloneFieldSet, info CloneInfo) error
}

// Clone implements Checker.Clone.
func (c *testChecker) Clone(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
	if c.onClone == nil {
		return nil
	}
	return c.onClone(ctx, mask, info)
}

func TestNoChecker(t *testing.T) {
	var s State
	if s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got true, wanted false")
	}
}

func TestCheckerNotRegisteredForPoint(t *testing.T) {
	var s State
	s.AppendChecker(&testChecker{}, &CheckerReq{})
	if s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got true, wanted false")
	}
}

func TestCheckerRegistered(t *testing.T) {
	var s State
	checkerCalled := false
	s.AppendChecker(&testChecker{onClone: func(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
		checkerCalled = true
		return nil
	}}, &CheckerReq{
		Points: []Point{PointClone},
		Clone: CloneFields{
			Credentials: true,
		},
	})

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	if !s.CloneReq().Contains(CloneFieldCredentials) {
		t.Errorf("CloneReq().Contains(CloneFieldCredentials): got false, wanted true")
	}
	if err := s.Clone(context.Background(), CloneFieldSet{}, &CloneInfo{}); err != nil {
		t.Errorf("Clone(): got %v, wanted nil", err)
	}
	if !checkerCalled {
		t.Errorf("Clone() did not call Checker.Clone()")
	}
}

func TestMultipleCheckersRegistered(t *testing.T) {
	var s State
	checkersCalled := [2]bool{}
	s.AppendChecker(&testChecker{onClone: func(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
		checkersCalled[0] = true
		return nil
	}}, &CheckerReq{
		Points: []Point{PointClone},
		Clone: CloneFields{
			Args: true,
		},
	})
	s.AppendChecker(&testChecker{onClone: func(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
		checkersCalled[1] = true
		return nil
	}}, &CheckerReq{
		Points: []Point{PointClone},
		Clone: CloneFields{
			Created: TaskFields{
				ThreadID: true,
			},
		},
	})

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	// CloneReq() should return the union of requested fields from all calls to
	// AppendChecker.
	req := s.CloneReq()
	if !req.Contains(CloneFieldArgs) {
		t.Errorf("req.Contains(CloneFieldArgs): got false, wanted true")
	}
	if !req.Created.Contains(TaskFieldThreadID) {
		t.Errorf("req.Created.Contains(TaskFieldThreadID): got false, wanted true")
	}
	if err := s.Clone(context.Background(), CloneFieldSet{}, &CloneInfo{}); err != nil {
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
	s.AppendChecker(&testChecker{onClone: func(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
		checkersCalled[0] = true
		return errFirstChecker
	}}, &CheckerReq{
		Points: []Point{PointClone},
	})
	s.AppendChecker(&testChecker{onClone: func(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
		checkersCalled[1] = true
		return errSecondChecker
	}}, &CheckerReq{
		Points: []Point{PointClone},
	})

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	if err := s.Clone(context.Background(), CloneFieldSet{}, &CloneInfo{}); err != errFirstChecker {
		t.Errorf("Clone(): got %v, wanted %v", err, errFirstChecker)
	}
	if !checkersCalled[0] {
		t.Errorf("Clone() did not call first Checker")
	}
	if checkersCalled[1] {
		t.Errorf("Clone() called second Checker")
	}
}
