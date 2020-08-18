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

type deletedState struct{}

func (*deletedState) Resize(ws console.WinSize) error {
	return fmt.Errorf("cannot resize a deleted process.ss")
}

func (*deletedState) Start(ctx context.Context) error {
	return fmt.Errorf("cannot start a deleted process.ss")
}

func (*deletedState) Delete(ctx context.Context) error {
	return fmt.Errorf("cannot delete a deleted process.ss: %w", errdefs.ErrNotFound)
}

func (*deletedState) Kill(ctx context.Context, sig uint32, all bool) error {
	return fmt.Errorf("cannot kill a deleted process.ss: %w", errdefs.ErrNotFound)
}

func (*deletedState) SetExited(status int) {}

func (*deletedState) Exec(ctx context.Context, path string, r *ExecConfig) (process.Process, error) {
	return nil, fmt.Errorf("cannot exec in a deleted state")
}
