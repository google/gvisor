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
	WaitReasonSelect      uint8 = 9  // +checkconst runtime waitReasonSelect
	WaitReasonChanReceive uint8 = 14 // +checkconst runtime waitReasonChanReceive
	WaitReasonSemacquire  uint8 = 18 // +checkconst runtime waitReasonSemacquire
)

// Values for the traceEv argument to gopark, from Go's src/runtime/trace.go.
const (
	TraceEvGoBlockRecv   byte = 23 // +checkconst runtime traceEvGoBlockRecv
	TraceEvGoBlockSelect byte = 24 // +checkconst runtime traceEvGoBlockSelect
	TraceEvGoBlockSync   byte = 25 // +checkconst runtime traceEvGoBlockSync
)
