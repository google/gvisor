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

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/pkg/process"
	runc "github.com/containerd/go-runc"
	"golang.org/x/sys/unix"
)

type stateTransition int

const (
	running stateTransition = iota
	stopped
	deleted
)

func (s stateTransition) String() string {
	switch s {
	case running:
		return "running"
	case stopped:
		return "stopped"
	case deleted:
		return "deleted"
	default:
		panic(fmt.Sprintf("unknown state: %d", s))
	}
}

type initState interface {
	Start(context.Context) error
	Delete(context.Context) error
	Exec(context.Context, string, *ExecConfig) (process.Process, error)
	State(ctx context.Context) (string, error)
	Stats(context.Context, string) (*runc.Stats, error)
	Kill(context.Context, uint32, bool) error
	SetExited(int)
}

type createdState struct {
	p *Init
}

func (s *createdState) name() string {
	return "created"
}

func (s *createdState) transition(transition stateTransition) {
	switch transition {
	case running:
		s.p.initState = &runningState{p: s.p}
	case stopped:
		s.p.initState = &stoppedState{process: s.p}
	case deleted:
		s.p.initState = &deletedState{}
	default:
		panic(fmt.Sprintf("invalid state transition %q to %q", s.name(), transition))
	}
}

func (s *createdState) Start(ctx context.Context) error {
	if err := s.p.start(ctx); err != nil {
		// Containerd doesn't allow deleting container in created state.
		// However, for gvisor, a non-root container in created state can
		// only go to running state. If the container can't be started,
		// it can only stay in created state, and never be deleted.
		// To work around that, we treat non-root container in start failure
		// state as stopped.
		if !s.p.Sandbox {
			s.p.io.Close()
			s.p.setExited(internalErrorCode)
			s.transition(stopped)
		}
		return err
	}
	s.transition(running)
	return nil
}

func (s *createdState) Delete(ctx context.Context) error {
	if err := s.p.delete(ctx); err != nil {
		return err
	}
	s.transition(deleted)
	return nil
}

func (s *createdState) Kill(ctx context.Context, sig uint32, all bool) error {
	return s.p.kill(ctx, sig, all)
}

func (s *createdState) SetExited(status int) {
	s.p.setExited(status)
	s.transition(stopped)
}

func (s *createdState) Exec(ctx context.Context, path string, r *ExecConfig) (process.Process, error) {
	return s.p.exec(path, r)
}

func (s *createdState) State(ctx context.Context) (string, error) {
	state, err := s.p.state(ctx)
	if err == nil && state == statusStopped {
		s.transition(stopped)
	}
	return state, err
}

func (s *createdState) Stats(ctx context.Context, id string) (*runc.Stats, error) {
	return s.p.stats(ctx, id)
}

type runningState struct {
	p *Init
}

func (s *runningState) name() string {
	return "running"
}

func (s *runningState) transition(transition stateTransition) {
	switch transition {
	case stopped:
		s.p.initState = &stoppedState{process: s.p}
	default:
		panic(fmt.Sprintf("invalid state transition %q to %q", s.name(), transition))
	}
}

func (s *runningState) Start(ctx context.Context) error {
	return fmt.Errorf("cannot start a running container")
}

func (s *runningState) Delete(ctx context.Context) error {
	return fmt.Errorf("cannot delete a running container")
}

func (s *runningState) Kill(ctx context.Context, sig uint32, all bool) error {
	return s.p.kill(ctx, sig, all)
}

func (s *runningState) SetExited(status int) {
	s.p.setExited(status)
	s.transition(stopped)
}

func (s *runningState) Exec(_ context.Context, path string, r *ExecConfig) (process.Process, error) {
	return s.p.exec(path, r)
}

func (s *runningState) State(ctx context.Context) (string, error) {
	state, err := s.p.state(ctx)
	if err == nil && state == "stopped" {
		s.transition(stopped)
	}
	return state, err
}

func (s *runningState) Stats(ctx context.Context, id string) (*runc.Stats, error) {
	return s.p.stats(ctx, id)
}

type stoppedState struct {
	process *Init
}

func (s *stoppedState) name() string {
	return "stopped"
}

func (s *stoppedState) transition(transition stateTransition) {
	switch transition {
	case deleted:
		s.process.initState = &deletedState{}
	default:
		panic(fmt.Sprintf("invalid state transition %q to %q", s.name(), transition))
	}
}

func (s *stoppedState) Start(context.Context) error {
	return fmt.Errorf("cannot start a stopped container")
}

func (s *stoppedState) Delete(ctx context.Context) error {
	if err := s.process.delete(ctx); err != nil {
		return err
	}
	s.transition(deleted)
	return nil
}

func (s *stoppedState) Kill(_ context.Context, signal uint32, _ bool) error {
	return handleStoppedKill(signal)
}

func (s *stoppedState) SetExited(status int) {
	s.process.setExited(status)
}

func (s *stoppedState) Exec(context.Context, string, *ExecConfig) (process.Process, error) {
	return nil, fmt.Errorf("cannot exec in a stopped state")
}

func (s *stoppedState) State(context.Context) (string, error) {
	return "stopped", nil
}

func (s *stoppedState) Stats(context.Context, string) (*runc.Stats, error) {
	return nil, fmt.Errorf("cannot stat a stopped container")
}

func handleStoppedKill(signal uint32) error {
	switch unix.Signal(signal) {
	case unix.SIGTERM, unix.SIGKILL:
		// Container is already stopped, so everything inside the container has
		// already been killed.
		return nil
	default:
		return errdefs.ToGRPCf(errdefs.ErrNotFound, "process not found")
	}
}
