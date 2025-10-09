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

// https://go.dev/cl/688335 (1.26) reorders waitreason runtime constants, adjusting the values of waitReasonSemacquire et al.
//go:build go1.26

package sync

// Values for the reason argument to gopark, from Go's src/runtime/runtime2.go.
const (
	WaitReasonSelect      uint8 = 18 // +checkconst runtime waitReasonSelect
	WaitReasonChanReceive uint8 = 19 // +checkconst runtime waitReasonChanReceive
	WaitReasonSemacquire  uint8 = 13 // +checkconst runtime waitReasonSemacquire
)
