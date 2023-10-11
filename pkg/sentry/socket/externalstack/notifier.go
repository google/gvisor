// Copyright 2023 The gVisor Authors.
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

package externalstack

import (
	"sync"

	"gvisor.dev/gvisor/pkg/sentry/stack"
)

// Notifier holds all the state necessary to issue notifications when
// IO events occur in the observed FDs.
type ExternalNotifier struct {
	// the epoll FD used to register for io notifications.
	epFD int32

	// mu protects fdMap.
	mu sync.Mutex

	// fdMap maps file descriptors to their notification queues
	// and waiting status.
	fdMap map[uint32]*stack.FdInfo
}

func (n *ExternalNotifier) AddFD(fd uint32, fi *stack.FdInfo) error {
	//TODO: implement glue layer
	return nil
}

func (n *ExternalNotifier) RemoveFD(fd uint32) {
	//TODO: implement glue layer
}

func (n *ExternalNotifier) UpdateFD(fd uint32) error {
	//TODO: implement glue layer
	return nil
}
