// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package tools

import "testing"

// TestIperf checks the Iperf parsers on sample output.
func TestIperf(t *testing.T) {
	sampleData := `
------------------------------------------------------------
Client connecting to 10.138.15.215, TCP port 32779
TCP window size: 45.0 KByte (default)
------------------------------------------------------------
[  3] local 10.138.15.216 port 32866 connected with 10.138.15.215 port 32779
[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-10.0 sec  459520 KBytes  45900 KBytes/sec
`
	i := Iperf{}
	bandwidth, err := i.bandwidth(sampleData)
	if err != nil || bandwidth != 45900 {
		t.Fatalf("failed with: %v and %f", err, bandwidth)
	}
}
