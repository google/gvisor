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
	"gvisor.dev/gvisor/pkg/fd"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func init() {
	RegisterSink(SinkDesc{
		Name: "test-sink",
		New:  newTestSink,
	})
}

type testSink struct {
	SinkDefaults

	onClone func(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error
}

var _ Sink = (*testSink)(nil)

func newTestSink(_ map[string]any, _ *fd.FD) (Sink, error) {
	return &testSink{}, nil
}

// Name implements Sink.Name.
func (c *testSink) Name() string {
	return "test-sink"
}

// Clone implements Sink.Clone.
func (c *testSink) Clone(ctx context.Context, fields FieldSet, info *pb.CloneInfo) error {
	if c.onClone == nil {
		return nil
	}
	return c.onClone(ctx, fields, info)
}

func TestNoSink(t *testing.T) {
	var s State
	if s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got true, wanted false")
	}
}

func TestSinkNotRegisteredForPoint(t *testing.T) {
	var s State
	s.AppendSink(&testSink{}, nil)
	if s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got true, wanted false")
	}
}

func TestSinkRegistered(t *testing.T) {
	var s State
	sinkCalled := false
	sink := &testSink{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			sinkCalled = true
			return nil
		},
	}
	req := []PointReq{
		{
			Pt:     PointClone,
			Fields: FieldSet{Context: MakeFieldMask(FieldCtxtCredentials)},
		},
	}
	s.AppendSink(sink, req)

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	fields := s.GetFieldSet(PointClone)
	if !fields.Context.Contains(FieldCtxtCredentials) {
		t.Errorf("fields.Context.Contains(PointContextCredentials): got false, wanted true")
	}
	if err := s.SentToSinks(func(c Sink) error {
		return c.Clone(context.Background(), fields, &pb.CloneInfo{})
	}); err != nil {
		t.Errorf("Clone(): got %v, wanted nil", err)
	}
	if !sinkCalled {
		t.Errorf("Clone() did not call Sink.Clone()")
	}
}

func TestMultipleSinksRegistered(t *testing.T) {
	var s State
	sinkCalled := [2]bool{}
	sink := &testSink{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			sinkCalled[0] = true
			return nil
		},
	}
	reqs := []PointReq{
		{Pt: PointClone},
	}
	s.AppendSink(sink, reqs)

	sink = &testSink{onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
		sinkCalled[1] = true
		return nil
	}}
	reqs = []PointReq{
		{Pt: PointClone},
	}
	s.AppendSink(sink, reqs)

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	// CloneReq() should return the union of requested fields from all calls to
	// AppendSink.
	fields := s.GetFieldSet(PointClone)
	if err := s.SentToSinks(func(c Sink) error {
		return c.Clone(context.Background(), fields, &pb.CloneInfo{})
	}); err != nil {
		t.Errorf("Clone(): got %v, wanted nil", err)
	}
	for i := range sinkCalled {
		if !sinkCalled[i] {
			t.Errorf("Clone() did not call Sink.Clone() index %d", i)
		}
	}
}

func TestCheckpointReturnsFirstSinkError(t *testing.T) {
	errFirstSink := errors.New("first Sink error")
	errSecondSink := errors.New("second Sink error")

	var s State
	sinkCalled := [2]bool{}
	sink := &testSink{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			sinkCalled[0] = true
			return errFirstSink
		},
	}
	reqs := []PointReq{
		{Pt: PointClone},
	}

	s.AppendSink(sink, reqs)

	sink = &testSink{
		onClone: func(context.Context, FieldSet, *pb.CloneInfo) error {
			sinkCalled[1] = true
			return errSecondSink
		},
	}
	s.AppendSink(sink, reqs)

	if !s.Enabled(PointClone) {
		t.Errorf("Enabled(PointClone): got false, wanted true")
	}
	if err := s.SentToSinks(func(c Sink) error {
		return c.Clone(context.Background(), FieldSet{}, &pb.CloneInfo{})
	}); err != errFirstSink {
		t.Errorf("Clone(): got %v, wanted %v", err, errFirstSink)
	}
	if !sinkCalled[0] {
		t.Errorf("Clone() did not call first Sink")
	}
	if sinkCalled[1] {
		t.Errorf("Clone() called second Sink")
	}
}

func TestFieldMaskEmpty(t *testing.T) {
	fd := FieldMask{}
	if !fd.Empty() {
		t.Errorf("new FieldMask must be empty: %+v", fd)
	}
}

func TestFieldMaskMake(t *testing.T) {
	zero := Field(0)
	one := Field(1)
	two := Field(2)
	fd := MakeFieldMask(zero, two)
	if fd.Empty() {
		t.Errorf("FieldMask must not be empty: %+v", fd)
	}
	if want := zero; !fd.Contains(want) {
		t.Errorf("FieldMask must contain %v: %+v", want, fd)
	}
	if want := two; !fd.Contains(want) {
		t.Errorf("FieldMask must contain %v: %+v", want, fd)
	}
	if want := one; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
}

func TestFieldMask(t *testing.T) {
	zero := Field(0)
	one := Field(1)
	two := Field(2)
	fd := FieldMask{}

	fd.Add(zero)
	if fd.Empty() {
		t.Errorf("FieldMask must not be empty: %+v", fd)
	}
	if want := zero; !fd.Contains(want) {
		t.Errorf("FieldMask must contain %v: %+v", want, fd)
	}
	if want := one; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
	if want := two; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}

	fd.Add(two)
	if fd.Empty() {
		t.Errorf("FieldMask must not be empty: %+v", fd)
	}
	if want := zero; !fd.Contains(want) {
		t.Errorf("FieldMask must contain %v: %+v", want, fd)
	}
	if want := one; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
	if want := two; !fd.Contains(want) {
		t.Errorf("FieldMask must contain %v: %+v", want, fd)
	}

	fd.Remove(zero)
	if fd.Empty() {
		t.Errorf("FieldMask must not be empty: %+v", fd)
	}
	if want := zero; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
	if want := one; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
	if want := two; !fd.Contains(want) {
		t.Errorf("FieldMask must contain %v: %+v", want, fd)
	}

	fd.Remove(two)
	if !fd.Empty() {
		t.Errorf("FieldMask must be empty: %+v", fd)
	}
	if want := zero; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
	if want := one; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
	if want := two; fd.Contains(want) {
		t.Errorf("FieldMask must not contain %v: %+v", want, fd)
	}
}
