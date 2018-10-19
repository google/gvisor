// Copyright 2018 Google LLC
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

// Scheduling policies, exposed by sched_getscheduler(2)/sched_setscheduler(2).
const (
	SCHED_NORMAL   = 0
	SCHED_FIFO     = 1
	SCHED_RR       = 2
	SCHED_BATCH    = 3
	SCHED_IDLE     = 5
	SCHED_DEADLINE = 6
	SCHED_MICROQ   = 16

	// SCHED_RESET_ON_FORK is a flag that indicates that the process is
	// reverted back to SCHED_NORMAL on fork.
	SCHED_RESET_ON_FORK = 0x40000000
)
