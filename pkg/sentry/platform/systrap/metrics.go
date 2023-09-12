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

package systrap

import (
	"gvisor.dev/gvisor/pkg/metric"
)

var (
	numSentryBoundSlowSwitches     = metric.MustCreateNewProfilingUint64Metric("/systrap/numSentryBoundSlowSwitches", false, "")
	numSentryBoundFastSwitches     = metric.MustCreateNewProfilingUint64Metric("/systrap/numSentryBoundFastSwitches", false, "")
	numTimesSentryFastPathDisabled = metric.MustCreateNewProfilingUint64Metric("/systrap/numTimesSentryFastPathDisabled", false, "")
	numTimesSentryFastPathEnabled  = metric.MustCreateNewProfilingUint64Metric("/systrap/numTimesSentryFastPathEnabled", false, "")
	numStubBoundSwitchesWithinHS   = metric.MustCreateNewProfilingUint64Metric("/systrap/numStubBoundSwitchesWithinHS", false, "")
	numStubBoundSwitchesWithinDS   = metric.MustCreateNewProfilingUint64Metric("/systrap/numStubBoundSwitchesWithinDS", false, "")
	numStubBoundSwitchesLong       = metric.MustCreateNewProfilingUint64Metric("/systrap/numStubBoundSwitchesLong", false, "")
	numTimesStubFastPathDisabled   = metric.MustCreateNewProfilingUint64Metric("/systrap/numTimesStubFastPathDisabled", false, "")
	numTimesStubFastPathEnabled    = metric.MustCreateNewProfilingUint64Metric("/systrap/numTimesStubFastPathEnabled", false, "")
	numTimesStubKicked             = metric.MustCreateNewProfilingUint64Metric("/systrap/numTimesStubKicked", false, "")
)
