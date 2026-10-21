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

//go:build amd64
// +build amd64

package kernel

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/cpuid"
)

// syncFPStateSize grows t's FP state once its thread group has been granted
// AMX, so that it holds tile data state.
func (t *Task) syncFPStateSize() {
	if t.tg.xcompPerm.Load()&cpuid.XCR0AmxDataMask != 0 {
		t.Arch().FloatingPointData().EnableAMX()
	}
}

// checkPlatformFeatures returns an error if k's feature set exposes AMX, which
// a restored application may be using, but k's platform cannot save and
// restore AMX state.
func (k *Kernel) checkPlatformFeatures() error {
	if k.featureSet.HasFeature(cpuid.X86FeatureAMX_TILE) && !k.Platform.SupportsAMX() {
		return fmt.Errorf("checkpoint exposes AMX, which this platform does not support")
	}
	return nil
}
