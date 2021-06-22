// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proc

import (
	"context"
	"fmt"

	"github.com/containerd/console"
)

type execState interface {
	Resize(console.WinSize) error
	Start(context.Context) error
	Delete(context.Context) error
	Kill(context.Context, uint32, bool) error
	SetExited(int)
}

type execCreatedState struct {
	p *execProcess
}

func (s *execCreatedState) name() string {
	return "created"
}

func (s *execCreatedState) transition(transition stateTransition) {
	switch transition {
	case running:
		s.p.execState = &execRunningState{p: s.p}
	case stopped:
		s.p.execState = &execStoppedState{p: s.p}
	case deleted:
		s.p.execState = &deletedState{}
	default:
		panic(fmt.Sprintf("invalid state transition %q to %q", s.name(), transition))
	}
}

func (s *execCreatedState) Resize(ws console.WinSize) error {
	return s.p.resize(ws)
}

func (s *execCreatedState) Start(ctx context.Context) error {
	if err := s.p.start(ctx); err != nil {
		return err
	}
	s.transition(running)
	return nil
}

func (s *execCreatedState) Delete(ctx context.Context) error {
	if err := s.p.delete(ctx); err != nil {
		return err
	}
	s.transition(deleted)
	return nil
}

func (s *execCreatedState) Kill(ctx context.Context, sig uint32, all bool) error {
	return s.p.kill(ctx, sig, all)
}

func (s *execCreatedState) SetExited(status int) {
	s.p.setExited(status)
	s.transition(stopped)
}

type execRunningState struct {
	p *execProcess
}

func (s *execRunningState) name() string {
	return "running"
}

func (s *execRunningState) transition(transition stateTransition) {
	switch transition {
	case stopped:
		s.p.execState = &execStoppedState{p: s.p}
	default:
		panic(fmt.Sprintf("invalid state transition %q to %q", s.name(), transition))
	}
}

func (s *execRunningState) Resize(ws console.WinSize) error {
	return s.p.resize(ws)
}

func (s *execRunningState) Start(context.Context) error {
	return fmt.Errorf("cannot start a running process")
}

func (s *execRunningState) Delete(context.Context) error {
	return fmt.Errorf("cannot delete a running process")
}

func (s *execRunningState) Kill(ctx context.Context, sig uint32, all bool) error {
	return s.p.kill(ctx, sig, all)
}

func (s *execRunningState) SetExited(status int) {
	s.p.setExited(status)
	s.transition(stopped)
}

type execStoppedState struct {
	p *execProcess
}

func (s *execStoppedState) name() string {
	return "stopped"
}

func (s *execStoppedState) transition(transition stateTransition) {
	switch transition {
	case deleted:
		s.p.execState = &deletedState{}
	default:
		panic(fmt.Sprintf("invalid state transition %q to %q", s.name(), transition))
	}
}

func (s *execStoppedState) Resize(console.WinSize) error {
	return fmt.Errorf("cannot resize a stopped container")
}

func (s *execStoppedState) Start(context.Context) error {
	return fmt.Errorf("cannot start a stopped process")
}

func (s *execStoppedState) Delete(ctx context.Context) error {
	if err := s.p.delete(ctx); err != nil {
		return err
	}
	s.transition(deleted)
	return nil
}

func (s *execStoppedState) Kill(_ context.Context, sig uint32, _ bool) error {
	return handleStoppedKill(sig)
}

func (s *execStoppedState) SetExited(int) {
	// no op
}
