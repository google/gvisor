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

package sync

// Values for the reason argument to gopark, from Go's src/runtime/runtime2.go.
const (
	WaitReasonSelect      uint8 = /*->*/ 0xff /*<- {{ Constant (Import "runtime") "waitReasonSelect" }} */
	WaitReasonChanReceive uint8 = /*->*/ 0xff /*<- {{ Constant (Import "runtime") "waitReasonChanReceive" }} */
	WaitReasonSemacquire  uint8 = /*->*/ 0xff /*<- {{ Constant (Import "runtime") "waitReasonSemacquire" }} */

	// WaitReasonSyncCondWait is the reason that sync.Cond.Wait parks with.
	//
	// It is one of the few reasons that testing/synctest considers to be
	// durably blocking, so goroutines that park with it don't prevent a
	// synctest bubble from becoming idle and advancing its fake clock. It is
	// for primitives that, like sync.Cond, park a goroutine until some other
	// goroutine explicitly wakes it.
	WaitReasonSyncCondWait uint8 = /*->*/ 0xff /*<- {{ Constant (Import "runtime") "waitReasonSyncCondWait" }} */
)
