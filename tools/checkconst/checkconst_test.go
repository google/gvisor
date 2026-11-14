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

package checkconst

import "testing"

func TestDefinePrefix(t *testing.T) {
	for _, tc := range []struct {
		line    string
		value   string
		wantErr bool
	}{
		{
			line:  "#define CPU_ERROR_CODE   CPU_ARCH_STATE+0  // +checkoffset . CPUArchState.errorCode",
			value: "0",
		},
		{
			line:  "#define CPU_STACK_TOP        CPU_STACK_BOTTOM+176               // +checksize . CPUArchState.stack",
			value: "176",
		},
		{
			line:  "#define SIGCTX_R8\tSIGMCTX+0   // +checkoffset arch SignalContext64.R8",
			value: "0",
		},
		{
			line:  "#define FOO BASE + OTHER + 8 // +checkoffset . T.f",
			value: "8",
		},
		{
			line:  "#define FOO 16 // +checkoffset . T.f",
			value: "16",
		},
		{
			line:    "#define CPU_ERROR_CODE 999 + 0 // +checkoffset . CPUArchState.errorCode",
			value:   "0",
			wantErr: true,
		},
		{
			line:    "#define FOO BASE + 0x10 + 8 // +checkoffset . T.f",
			value:   "8",
			wantErr: true,
		},
	} {
		m := defineRegexp.FindStringSubmatch(tc.line)
		if m == nil {
			t.Errorf("defineRegexp didn't match %q", tc.line)
			continue
		}
		if m[2] != tc.value {
			t.Errorf("defineRegexp(%q) checked value = %q, want %q", tc.line, m[2], tc.value)
		}
		err := checkDefinePrefix(m[1])
		if gotErr := err != nil; gotErr != tc.wantErr {
			t.Errorf("checkDefinePrefix(%q) for %q = %v, want error: %t", m[1], tc.line, err, tc.wantErr)
		}
	}
}
