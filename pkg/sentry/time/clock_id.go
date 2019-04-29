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

package time

import (
	"strconv"
)

// ClockID is a Linux clock identifier.
type ClockID int32

// These are the supported Linux clock identifiers.
const (
	Realtime ClockID = iota
	Monotonic
)

// String implements fmt.Stringer.String.
func (c ClockID) String() string {
	switch c {
	case Realtime:
		return "Realtime"
	case Monotonic:
		return "Monotonic"
	default:
		return strconv.Itoa(int(c))
	}
}
