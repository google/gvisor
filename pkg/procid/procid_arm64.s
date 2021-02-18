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

// +build arm64
// +build go1.8
// +build !go1.18

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
