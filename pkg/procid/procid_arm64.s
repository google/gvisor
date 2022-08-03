// Copyright 2018 The gVisor Authors.
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

//go:build arm64 && go1.8 && !go1.21 && go1.1
// +build arm64,go1.8,!go1.21,go1.1

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

#include "textflag.h"

TEXT ·Current(SB),NOSPLIT,$0-8
	// The offset specified here is the m_procid offset for Go1.8+.
	// Changes to this offset should be caught by the tests, and major
	// version changes require an explicit tag change above.
	MOVD g, R0      // g
	MOVD 48(R0), R0 // g_m (may change in future versions)
	MOVD 72(R0), R0 // m_procid (may change in future versions)
	MOVD R0, ret+0(FP)
	RET
