// Copyright 2019 The gVisor Authors.
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

package gofer

import (
	"gvisor.dev/gvisor/pkg/usermem"
)

// This are equivalent to usermem.Addr.RoundDown/Up, but without the
// potentially truncating conversion to usermem.Addr. This is necessary because
// there is no way to define generic "PageRoundDown/Up" functions in Go.

func pageRoundDown(x uint64) uint64 {
	return x &^ (usermem.PageSize - 1)
}

func pageRoundUp(x uint64) uint64 {
	return pageRoundDown(x + usermem.PageSize - 1)
}
