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

// +build go1.9
// +build !go1.14

// Check go:linkname function signatures when updating Go version.

package tcpip

import (
	"time"     // Used with go:linkname.
	_ "unsafe" // Required for go:linkname.
)

// StdClock implements Clock with the time package.
type StdClock struct{}

var _ Clock = (*StdClock)(nil)

//go:linkname now time.now
func now() (sec int64, nsec int32, mono int64)

// Now implements Clock.Now.
func (*StdClock) Now() time.Time {
	sec, nsec, _ := now()
	return time.Unix(sec, int64(nsec))
}

// NowMonotonic implements Clock.NowMonotonic.
func (*StdClock) NowMonotonic() MonotonicTime {
	_, _, mono := now()
	return NewMonotonicTime(0, mono)
}

// Since implements Clock.Since.
func (s *StdClock) Since(since time.Time) time.Duration {
	return s.Now().Sub(since)
}

// SinceMonotonic implements Clock.SinceMonotonic.
func (s *StdClock) SinceMonotonic(since MonotonicTime) time.Duration {
	return s.NowMonotonic().Sub(since)
}
