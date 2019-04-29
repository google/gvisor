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
	"testing"
)

func TestVersionNumberEquivalent(t *testing.T) {
	for i := uint32(0); i < 1024; i++ {
		str := versionString(i)
		version, ok := parseVersion(str)
		if !ok {
			t.Errorf("#%d: parseVersion(%q) failed, want success", i, str)
			continue
		}
		if i != version {
			t.Errorf("#%d: got version %d, want %d", i, i, version)
		}
	}
}

func TestVersionStringEquivalent(t *testing.T) {
	// There is one case where the version is not equivalent on purpose,
	// that is 9P2000.L.Google.0.  It is not equivalent because versionString
	// must always return the more generic 9P2000.L for legacy servers that
	// check for it.  See net/9p/client.c.
	str := "9P2000.L.Google.0"
	version, ok := parseVersion(str)
	if !ok {
		t.Errorf("parseVersion(%q) failed, want success", str)
	}
	if got := versionString(version); got != "9P2000.L" {
		t.Errorf("versionString(%d) got %q, want %q", version, got, "9P2000.L")
	}

	for _, test := range []struct {
		versionString string
	}{
		{
			versionString: "9P2000.L",
		},
		{
			versionString: "9P2000.L.Google.1",
		},
		{
			versionString: "9P2000.L.Google.347823894",
		},
	} {
		version, ok := parseVersion(test.versionString)
		if !ok {
			t.Errorf("parseVersion(%q) failed, want success", test.versionString)
			continue
		}
		if got := versionString(version); got != test.versionString {
			t.Errorf("versionString(%d) got %q, want %q", version, got, test.versionString)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, test := range []struct {
		versionString   string
		expectSuccess   bool
		expectedVersion uint32
	}{
		{
			versionString: "9P",
			expectSuccess: false,
		},
		{
			versionString: "9P.L",
			expectSuccess: false,
		},
		{
			versionString: "9P200.L",
			expectSuccess: false,
		},
		{
			versionString: "9P2000",
			expectSuccess: false,
		},
		{
			versionString: "9P2000.L.Google.-1",
			expectSuccess: false,
		},
		{
			versionString: "9P2000.L.Google.",
			expectSuccess: false,
		},
		{
			versionString: "9P2000.L.Google.3546343826724305832",
			expectSuccess: false,
		},
		{
			versionString: "9P2001.L",
			expectSuccess: false,
		},
		{
			versionString:   "9P2000.L",
			expectSuccess:   true,
			expectedVersion: 0,
		},
		{
			versionString:   "9P2000.L.Google.0",
			expectSuccess:   true,
			expectedVersion: 0,
		},
		{
			versionString:   "9P2000.L.Google.1",
			expectSuccess:   true,
			expectedVersion: 1,
		},
	} {
		version, ok := parseVersion(test.versionString)
		if ok != test.expectSuccess {
			t.Errorf("parseVersion(%q) got (_, %v), want (_, %v)", test.versionString, ok, test.expectSuccess)
			continue
		}
		if !test.expectSuccess {
			continue
		}
		if version != test.expectedVersion {
			t.Errorf("parseVersion(%q) got (%d, _), want (%d, _)", test.versionString, version, test.expectedVersion)
		}
	}
}

func BenchmarkParseVersion(b *testing.B) {
	for n := 0; n < b.N; n++ {
		parseVersion("9P2000.L.Google.1")
	}
}
