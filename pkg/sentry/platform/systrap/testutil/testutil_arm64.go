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

//go:build arm64
// +build arm64

// Package testutil provides common test utilities for systrap.
package testutil

// UserCode is the user program: for (;;) getpid();
var UserCode = []byte{
	0x88, 0x15, 0x80, 0xd2, // mov x8, #172 (SYS_getpid)
	0x01, 0x00, 0x00, 0xd4, // svc #0
	0xfe, 0xff, 0xff, 0x17, // b .-8
}
