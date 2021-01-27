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

package p9

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// highestSupportedVersion is the highest supported version X in a
	// version string of the format 9P2000.L.Google.X.
	//
	// Clients are expected to start requesting this version number and
	// to continuously decrement it until a Tversion request succeeds.
	highestSupportedVersion uint32 = 13

	// lowestSupportedVersion is the lowest supported version X in a
	// version string of the format 9P2000.L.Google.X.
	//
	// Clients are free to send a Tversion request at a version below this
	// value but are expected to encounter an Rlerror in response.
	lowestSupportedVersion uint32 = 0

	// baseVersion is the base version of 9P that this package must always
	// support.  It is equivalent to 9P2000.L.Google.0.
	baseVersion = "9P2000.L"
)

// HighestVersionString returns the highest possible version string that a client
// may request or a server may support.
func HighestVersionString() string {
	return versionString(highestSupportedVersion)
}

// parseVersion parses a Tversion version string into a numeric version number
// if the version string is supported by p9.  Otherwise returns (0, false).
//
// From Tversion(9P): "Version strings are defined such that, if the client string
// contains one or more period characters, the initial substring up to but not
// including any single period in the version string defines a version of the protocol."
//
// p9 intentionally diverges from this and always requires that the version string
// start with 9P2000.L to express that it is always compatible with 9P2000.L.  The
// only supported versions extensions are of the format 9p2000.L.Google.X where X
// is an ever increasing version counter.
//
// Version 9P2000.L.Google.0 implies 9P2000.L.
//
// New versions must always be a strict superset of 9P2000.L. A version increase must
// define a predicate representing the feature extension introduced by that version. The
// predicate must be commented and should take the format:
//
// // VersionSupportsX returns true if version v supports X and must be checked when ...
// func VersionSupportsX(v int32) bool {
//	...
// )
func parseVersion(str string) (uint32, bool) {
	// Special case the base version which lacks the ".Google.X" suffix.  This
	// version always means version 0.
	if str == baseVersion {
		return 0, true
	}
	substr := strings.Split(str, ".")
	if len(substr) != 4 {
		return 0, false
	}
	if substr[0] != "9P2000" || substr[1] != "L" || substr[2] != "Google" || len(substr[3]) == 0 {
		return 0, false
	}
	version, err := strconv.ParseUint(substr[3], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(version), true
}

// versionString formats a p9 version number into a Tversion version string.
func versionString(version uint32) string {
	// Special case the base version so that clients expecting this string
	// instead of the 9P2000.L.Google.0 equivalent get it.  This is important
	// for backwards compatibility with legacy servers that check for exactly
	// the baseVersion and allow nothing else.
	if version == 0 {
		return baseVersion
	}
	return fmt.Sprintf("9P2000.L.Google.%d", version)
}

// VersionSupportsTflushf returns true if version v supports the Tflushf message.
// This predicate must be checked by clients before attempting to make a Tflushf
// request.  If this predicate returns false, then clients may safely no-op.
func VersionSupportsTflushf(v uint32) bool {
	return v >= 1
}

// versionSupportsTwalkgetattr returns true if version v supports the
// Twalkgetattr message. This predicate must be checked by clients before
// attempting to make a Twalkgetattr request.
func versionSupportsTwalkgetattr(v uint32) bool {
	return v >= 2
}

// versionSupportsTucreation returns true if version v supports the Tucreation
// messages (Tucreate, Tusymlink, Tumkdir, Tumknod). This predicate must be
// checked by clients before attempting to make a Tucreation request.
// If Tucreation messages are not supported, their non-UID supporting
// counterparts (Tlcreate, Tsymlink, Tmkdir, Tmknod) should be used.
func versionSupportsTucreation(v uint32) bool {
	return v >= 3
}

// VersionSupportsConnect returns true if version v supports the Tlconnect
// message. This predicate must be checked by clients
// before attempting to make a Tlconnect request. If Tlconnect messages are not
// supported, Tlopen should be used.
func VersionSupportsConnect(v uint32) bool {
	return v >= 4
}

// VersionSupportsAnonymous returns true if version v supports Tlconnect
// with the AnonymousSocket mode. This predicate must be checked by clients
// before attempting to use the AnonymousSocket Tlconnect mode.
func VersionSupportsAnonymous(v uint32) bool {
	return v >= 5
}

// VersionSupportsMultiUser returns true if version v supports multi-user fake
// directory permissions and ID values.
func VersionSupportsMultiUser(v uint32) bool {
	return v >= 6
}

// versionSupportsTallocate returns true if version v supports Allocate().
func versionSupportsTallocate(v uint32) bool {
	return v >= 7
}

// versionSupportsFlipcall returns true if version v supports IPC channels from
// the flipcall package. Note that these must be negotiated, but this version
// string indicates that such a facility exists.
func versionSupportsFlipcall(v uint32) bool {
	return v >= 8
}

// VersionSupportsOpenTruncateFlag returns true if version v supports
// passing the OpenTruncate flag to Tlopen.
func VersionSupportsOpenTruncateFlag(v uint32) bool {
	return v >= 9
}

// versionSupportsGetSetXattr returns true if version v supports
// the Tgetxattr and Tsetxattr messages.
func versionSupportsGetSetXattr(v uint32) bool {
	return v >= 10
}

// versionSupportsListRemoveXattr returns true if version v supports
// the Tlistxattr and Tremovexattr messages.
func versionSupportsListRemoveXattr(v uint32) bool {
	return v >= 11
}

// versionSupportsTsetattrclunk returns true if version v supports
// the Tsetattrclunk message.
func versionSupportsTsetattrclunk(v uint32) bool {
	return v >= 12
}

// VersionSupportsTwalkRevalidate returns true if version v supports
// the TwalkRevalidate message.
func VersionSupportsTwalkRevalidate(v uint32) bool {
	return v >= 13
}
