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

package control

import "testing"

func TestParseTPUTaskInfo(t *testing.T) {
	tests := []struct {
		hexFd     string
		wantReqFd int32
		wantRspFd int32
		wantErr   bool
	}{
		{hexFd: "00030004", wantReqFd: 3, wantRspFd: 4},
		{hexFd: "001a002b", wantReqFd: 0x1a, wantRspFd: 0x2b},
		{hexFd: "BAD", wantErr: true},
		{hexFd: "ZZZZ0004", wantErr: true},
		{hexFd: "0003ZZZZ", wantErr: true},
	}

	for _, tc := range tests {
		info, err := parseTPUTaskInfo(nil /* task */, tc.hexFd)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseTPUTaskInfo(%q) err = %v, wantErr = %v", tc.hexFd, err, tc.wantErr)
			continue
		}
		if tc.wantErr {
			continue
		}
		if info.reqWriteFd != tc.wantReqFd || info.rspReadFd != tc.wantRspFd {
			t.Errorf("parseTPUTaskInfo(%q) = (%d, %d), want (%d, %d)", tc.hexFd, info.reqWriteFd, info.rspReadFd, tc.wantReqFd, tc.wantRspFd)
		}
	}
}
