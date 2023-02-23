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

package systrap

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

const syscallStubMessageOffset = hostarch.PageSize

// syscallSentryMessage is a shared message that can be changed only from the
// Sentry and a stub process can only read it.
type syscallSentryMessage struct {
	state  uint32
	unused uint32
	sysno  uint64
	args   [6]uint64
}

// syscallStubMessage is a shared message that can be changed from a stub
// process. It is used to notify the Sentry that a requested system call has
// been executed.
//
// Attention: It can be compromised by user threads.
type syscallStubMessage struct {
	ret uint64
}
