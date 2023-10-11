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

package stack

import "gvisor.dev/gvisor/pkg/waiter"

type FdInfo struct {
	Queue   *waiter.Queue
	Mask    waiter.EventMask
	Ready   waiter.EventMask
	Waiting bool `state:"nosave"`
}

type Notifier interface {
	AddFD(fd uint32, fi *FdInfo) error

	RemoveFD(fd uint32)

	UpdateFD(fd uint32) error
}
