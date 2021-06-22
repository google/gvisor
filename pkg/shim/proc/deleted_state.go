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
	runc "github.com/containerd/go-runc"
)

type deletedState struct{}

func (*deletedState) Resize(console.WinSize) error {
	return fmt.Errorf("cannot resize a deleted container/process")
}

func (*deletedState) Start(context.Context) error {
	return fmt.Errorf("cannot start a deleted container/process")
}

func (*deletedState) Delete(context.Context) error {
	return fmt.Errorf("cannot delete a deleted container/process: %w", errdefs.ErrNotFound)
}

func (*deletedState) Kill(_ context.Context, signal uint32, _ bool) error {
	return handleStoppedKill(signal)
}

func (*deletedState) SetExited(int) {}

func (*deletedState) Exec(context.Context, string, *ExecConfig) (process.Process, error) {
	return nil, fmt.Errorf("cannot exec in a deleted state")
}

func (s *deletedState) State(context.Context) (string, error) {
	// There is no "deleted" state, closest one is stopped.
	return "stopped", nil
}

func (s *deletedState) Stats(context.Context, string) (*runc.Stats, error) {
	return nil, fmt.Errorf("cannot stat a stopped container/process")
}
