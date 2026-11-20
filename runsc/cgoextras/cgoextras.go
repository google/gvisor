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

// Package cgoextras provides cgo-only runtime workarounds and initialization
// for runsc and sentry binaries.
//
// In pure-Go binaries (CGO_ENABLED=0), cgo code in this package is not built.
// When cgo is enabled (e.g., -race, network plugins), this package is compiled
// with cgo and runs early process initialization such as disabling host ARM64
// Pointer Authentication (PAC) keys via an ELF .init_array constructor before
// libpthread or the Go runtime spawns threads.
package cgoextras
