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

package systrap

import (
	"encoding/json"
	"testing"
)

func TestDecodePACKeys(t *testing.T) {
	address := [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	generic := [2]uint64{9, 10}
	enabled := uint64(0)
	for _, test := range []struct {
		name    string
		keys    pacKeys
		wantErr bool
	}{
		{name: "address and generic", keys: pacKeys{Version: pacKeysVersion, Address: &address, Generic: &generic}},
		{name: "address only", keys: pacKeys{Version: pacKeysVersion, Address: &address}},
		{name: "generic only", keys: pacKeys{Version: pacKeysVersion, Generic: &generic}},
		{name: "address and enabled", keys: pacKeys{Version: pacKeysVersion, Address: &address, Enabled: &enabled}},
		{name: "enabled without address", keys: pacKeys{Version: pacKeysVersion, Generic: &generic, Enabled: &enabled}, wantErr: true},
		{name: "empty", keys: pacKeys{Version: pacKeysVersion}, wantErr: true},
		{name: "unknown version", keys: pacKeysVersion2(&address), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(&test.keys)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			got, err := decodePACKeys(data)
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("decodePACKeys(%s) error = %v, want error %t", data, err, test.wantErr)
			}
			if err != nil {
				return
			}
			if (got.Address == nil) != (test.keys.Address == nil) || (got.Address != nil && *got.Address != *test.keys.Address) {
				t.Errorf("Address = %v, want %v", got.Address, test.keys.Address)
			}
			if (got.Generic == nil) != (test.keys.Generic == nil) || (got.Generic != nil && *got.Generic != *test.keys.Generic) {
				t.Errorf("Generic = %v, want %v", got.Generic, test.keys.Generic)
			}
			if (got.Enabled == nil) != (test.keys.Enabled == nil) || (got.Enabled != nil && *got.Enabled != *test.keys.Enabled) {
				t.Errorf("Enabled = %v, want %v", got.Enabled, test.keys.Enabled)
			}
		})
	}
}

func pacKeysVersion2(address *[8]uint64) pacKeys {
	return pacKeys{Version: pacKeysVersion + 1, Address: address}
}

func TestDecodePACKeysRejectsGarbage(t *testing.T) {
	if _, err := decodePACKeys([]byte("0011223344")); err == nil {
		t.Error("decodePACKeys of a hex string succeeded, want error")
	}
}

func TestPACKeysCheckHost(t *testing.T) {
	address := new([8]uint64)
	generic := new([2]uint64)
	for _, test := range []struct {
		name    string
		keys    pacKeys
		host    hostPAC
		wantErr bool
	}{
		{name: "all supported", keys: pacKeys{Address: address, Generic: generic}, host: hostPAC{address: true, generic: true}},
		{name: "no host support", keys: pacKeys{Address: address, Generic: generic}, host: hostPAC{}, wantErr: true},
		{name: "no generic support", keys: pacKeys{Address: address, Generic: generic}, host: hostPAC{address: true}, wantErr: true},
		{name: "no address support", keys: pacKeys{Address: address}, host: hostPAC{generic: true}, wantErr: true},
		{name: "address keys only", keys: pacKeys{Address: address}, host: hostPAC{address: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.keys.checkHost(test.host); (err != nil) != test.wantErr {
				t.Errorf("checkHost(%+v) error = %v, want error %t", test.host, err, test.wantErr)
			}
		})
	}
}
