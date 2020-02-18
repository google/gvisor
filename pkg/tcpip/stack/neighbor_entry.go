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

package stack

import (
	"fmt"
)

// NeighborState defines the state of a NeighborEntry within the Neighbor
// Unreachability Detection state machine, as per RFC 4861 section 7.3.2.
type NeighborState uint8

const (
	// NEW is the initial state of entries that have been created automatically
	// by the Neighbor Unreachabilility Detection state machine.
	NEW NeighborState = iota
	// INCOMPLETE means that there is an outstanding request to resolve the
	// address. This is the initial state.
	INCOMPLETE
	// REACHABLE means the path to the neighbor is functioning properly for both
	// receive and transmit paths.
	REACHABLE
	// STALE means reachability to the neighbor is unknown, but packets are still
	// able to be transmitted to the possibly stale link address.
	STALE
	// DELAY means reachability to the neighbor is unknown and pending
	// confirmation from an upper-level protocol like TCP, but packets are still
	// able to be transmitted to the possibly stale link address.
	DELAY
	// PROBE means a reachability confirmation is actively being sought by
	// periodically retrasmitting reachability probes until a reachability
	// confirmation is received, or until the max amount of probes has been sent.
	PROBE
	// STATIC describes entries that have been explicited added by the user. They
	// do not expire and are not deleted until explicitly removed.
	STATIC
	// FAILED means traffic should not be sent to this neighbor since attempts of
	// reachability have returned inconclusive.
	FAILED
)

// String implements Stringer.
func (s NeighborState) String() string {
	switch s {
	case NEW:
		return "new"
	case INCOMPLETE:
		return "incomplete"
	case REACHABLE:
		return "reachable"
	case STALE:
		return "stale"
	case DELAY:
		return "delay"
	case PROBE:
		return "probe"
	case STATIC:
		return "static"
	case FAILED:
		return "failed"
	default:
		return fmt.Sprintf("unknown (%d)", s)
	}
}
