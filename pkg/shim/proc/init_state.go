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
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/pkg/process"
)

type initState interface {
	Resize(console.WinSize) error
	Start(context.Context) error
	Delete(context.Context) error
	Exec(context.Context, string, *ExecConfig) (process.Process, error)
	Kill(context.Context, uint32, bool) error
	SetExited(int)
}

type createdState struct {
	p *Init
}

func (s *createdState) transition(name string) error {
	switch name {
	case "running":
		s.p.initState = &runningState{p: s.p}
	case "stopped":
		s.p.initState = &stoppedState{p: s.p}
	case "deleted":
		s.p.initState = &deletedState{}
	default:
		return fmt.Errorf("invalid state transition %q to %q", stateName(s), name)
	}
	return nil
}

func (s *createdState) Resize(ws console.WinSize) error {
	return s.p.resize(ws)
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
			if err := s.transition("stopped"); err != nil {
				panic(err)
			}
		}
		return err
	}
	return s.transition("running")
}

func (s *createdState) Delete(ctx context.Context) error {
	if err := s.p.delete(ctx); err != nil {
		return err
	}
	return s.transition("deleted")
}

func (s *createdState) Kill(ctx context.Context, sig uint32, all bool) error {
	return s.p.kill(ctx, sig, all)
}

func (s *createdState) SetExited(status int) {
	s.p.setExited(status)

	if err := s.transition("stopped"); err != nil {
		panic(err)
	}
}

func (s *createdState) Exec(ctx context.Context, path string, r *ExecConfig) (process.Process, error) {
	return s.p.exec(path, r)
}

type runningState struct {
	p *Init
}

func (s *runningState) transition(name string) error {
	switch name {
	case "stopped":
		s.p.initState = &stoppedState{p: s.p}
	default:
		return fmt.Errorf("invalid state transition %q to %q", stateName(s), name)
	}
	return nil
}

func (s *runningState) Resize(ws console.WinSize) error {
	return s.p.resize(ws)
}

func (s *runningState) Start(ctx context.Context) error {
	return fmt.Errorf("cannot start a running process.ss")
}

func (s *runningState) Delete(ctx context.Context) error {
	return fmt.Errorf("cannot delete a running process.ss")
}

func (s *runningState) Kill(ctx context.Context, sig uint32, all bool) error {
	return s.p.kill(ctx, sig, all)
}

func (s *runningState) SetExited(status int) {
	s.p.setExited(status)

	if err := s.transition("stopped"); err != nil {
		panic(err)
	}
}

func (s *runningState) Exec(ctx context.Context, path string, r *ExecConfig) (process.Process, error) {
	return s.p.exec(path, r)
}

type stoppedState struct {
	p *Init
}

func (s *stoppedState) transition(name string) error {
	switch name {
	case "deleted":
		s.p.initState = &deletedState{}
	default:
		return fmt.Errorf("invalid state transition %q to %q", stateName(s), name)
	}
	return nil
}

func (s *stoppedState) Resize(ws console.WinSize) error {
	return fmt.Errorf("cannot resize a stopped container")
}

func (s *stoppedState) Start(ctx context.Context) error {
	return fmt.Errorf("cannot start a stopped process.ss")
}

func (s *stoppedState) Delete(ctx context.Context) error {
	if err := s.p.delete(ctx); err != nil {
		return err
	}
	return s.transition("deleted")
}

func (s *stoppedState) Kill(ctx context.Context, sig uint32, all bool) error {
	return errdefs.ToGRPCf(errdefs.ErrNotFound, "process.ss %s not found", s.p.id)
}

func (s *stoppedState) SetExited(status int) {
	// no op
}

func (s *stoppedState) Exec(ctx context.Context, path string, r *ExecConfig) (process.Process, error) {
	return nil, fmt.Errorf("cannot exec in a stopped state")
}
