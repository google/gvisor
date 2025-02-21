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
	"time"

	runc "github.com/containerd/go-runc"
	"github.com/gogo/protobuf/types"
)

// Mount holds filesystem mount configuration.
type Mount struct {
	Type    string
	Source  string
	Target  string
	Options []string
}

// CreateConfig hold task creation configuration.
type CreateConfig struct {
	ID       string
	Bundle   string
	Runtime  string
	Rootfs   []Mount
	Terminal bool
	Stdin    string
	Stdout   string
	Stderr   string
}

// ExecConfig holds exec creation configuration.
type ExecConfig struct {
	ID       string
	Terminal bool
	Stdin    string
	Stdout   string
	Stderr   string
	Spec     *types.Any
}

// Exit is the type of exit events.
type Exit struct {
	Timestamp time.Time
	ID        string
	Status    int
}

// ProcessMonitor monitors process exit changes.
type ProcessMonitor interface {
	// Subscribe to process exit changes
	Subscribe() chan runc.Exit
	// Unsubscribe to process exit changes
	Unsubscribe(c chan runc.Exit)
}
