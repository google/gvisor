// Copyright 2026 The gVisor Authors.
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

package linux

// Flags for pidfd_open() from include/uapi/linux/pidfd.h.
const (
	PIDFD_NONBLOCK = O_NONBLOCK
	PIDFD_THREAD   = O_EXCL
)

// Flags for pidfd_send_signal().
const (
	PIDFD_SIGNAL_THREAD        = 1 << 0
	PIDFD_SIGNAL_THREAD_GROUP  = 1 << 1
	PIDFD_SIGNAL_PROCESS_GROUP = 1 << 2
)
