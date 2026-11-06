// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/sys/unix"
)

func TestDevicesV1Writes(t *testing.T) {
	rules := []DeviceRule{
		{Type: "c", Major: 1, Minor: 3, Access: "rw"},
		{Type: "c", Major: 136, Minor: DeviceAny, Access: "rw"},
		{Type: "c", Major: 0, Minor: 0, Access: "m"},
	}
	for _, tc := range []struct {
		name  string
		list  string
		rules []DeviceRule
		want  []cgroupWrite
	}{
		{
			name:  "new cgroup",
			list:  "a *:* rwm\n",
			rules: rules,
			want: []cgroupWrite{
				{"devices.deny", "a"},
				{"devices.allow", "c 0:0 m"},
				{"devices.allow", "c 136:* rw"},
				{"devices.allow", "c 1:3 rw"},
			},
		},
		{
			name:  "already set",
			list:  "c 1:3 rw\nc 136:* rw\nc 0:0 m\n",
			rules: rules,
			want:  nil,
		},
		{
			name:  "extend",
			list:  "c 1:3 rwm\nc 136:* rw\nc 10:229 rw\n",
			rules: rules,
			want:  []cgroupWrite{{"devices.allow", "c 0:0 m"}},
		},
		{
			name: "merged accesses",
			list: "",
			rules: []DeviceRule{
				{Type: "c", Major: 1, Minor: 3, Access: "w"},
				{Type: "c", Major: 1, Minor: 3, Access: "mr"},
			},
			want: []cgroupWrite{{"devices.allow", "c 1:3 rwm"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := devicesV1Writes(tc.list, tc.rules)
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(cgroupWrite{}), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("devicesV1Writes() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeviceFilter(t *testing.T) {
	got, err := deviceFilter([]DeviceRule{
		{Type: "c", Major: 1, Minor: 3, Access: "rw"},
		{Type: "b", Major: 8, Minor: DeviceAny, Access: "rwm"},
		{Type: "c", Major: DeviceAny, Minor: DeviceAny, Access: "m"},
	})
	if err != nil {
		t.Fatalf("deviceFilter(): %v", err)
	}
	jump := func(i insn, off int16) insn {
		i.Off = off
		return i
	}
	want := []insn{
		ldxw(r2, r1, 0),
		alu32(unix.BPF_AND, r2, 0xffff),
		ldxw(r3, r1, 0),
		alu32(unix.BPF_RSH, r3, 16),
		ldxw(r4, r1, 4),
		ldxw(r5, r1, 8),
		// c 1:3 rw
		jump(jneImm(r2, unix.BPF_DEVCG_DEV_CHAR), 7),
		mov32(r1, r3),
		alu32(unix.BPF_AND, r1, unix.BPF_DEVCG_ACC_READ|unix.BPF_DEVCG_ACC_WRITE),
		jump(jneReg(r1, r3), 4),
		jump(jneImm(r4, 1), 3),
		jump(jneImm(r5, 3), 2),
		alu32(unix.BPF_MOV, r0, 1),
		exit,
		// b 8:* rwm
		jump(jneImm(r2, unix.BPF_DEVCG_DEV_BLOCK), 3),
		jump(jneImm(r4, 8), 2),
		alu32(unix.BPF_MOV, r0, 1),
		exit,
		// c *:* m
		jump(jneImm(r2, unix.BPF_DEVCG_DEV_CHAR), 5),
		mov32(r1, r3),
		alu32(unix.BPF_AND, r1, unix.BPF_DEVCG_ACC_MKNOD),
		jump(jneReg(r1, r3), 2),
		alu32(unix.BPF_MOV, r0, 1),
		exit,
		// Deny everything else.
		alu32(unix.BPF_MOV, r0, 0),
		exit,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("deviceFilter() diff (-want +got):\n%s", diff)
	}
}

func TestDeviceFilterInvalid(t *testing.T) {
	for _, r := range []DeviceRule{
		{Type: "a", Major: 1, Minor: 3, Access: "rw"},
		{Type: "c", Major: 1, Minor: 3, Access: "rx"},
		{Type: "c", Major: 1, Minor: 3, Access: ""},
		{Type: "c", Major: 1 << 40, Minor: 3, Access: "rw"},
	} {
		if _, err := deviceFilter([]DeviceRule{r}); err == nil {
			t.Errorf("deviceFilter(%q) succeeded, want error", r)
		}
	}
}
