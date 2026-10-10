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
	cpu := pacCPU{Implementer: 1, Architecture: 2, Variant: 3, Part: 4, Revision: 5}
	for _, test := range []struct {
		name    string
		keys    pacKeys
		wantErr bool
	}{
		{name: "address and generic", keys: pacKeys{Version: pacKeysVersion, Address: &address, Generic: &generic, AddressAlgorithm: pacAlgorithmQARMA5, GenericAlgorithm: pacAlgorithmQARMA3}},
		{name: "address only", keys: pacKeys{Version: pacKeysVersion, Address: &address, AddressAlgorithm: pacAlgorithmQARMA5}},
		{name: "generic only", keys: pacKeys{Version: pacKeysVersion, Generic: &generic, GenericAlgorithm: pacAlgorithmQARMA3}},
		{name: "implementation defined", keys: pacKeys{Version: pacKeysVersion, Address: &address, AddressAlgorithm: pacAlgorithmIMPDEF, CPU: &cpu}},
		{name: "address and enabled", keys: pacKeys{Version: pacKeysVersion, Address: &address, AddressAlgorithm: pacAlgorithmQARMA5, Enabled: &enabled}},
		{name: "enabled without address", keys: pacKeys{Version: pacKeysVersion, Generic: &generic, GenericAlgorithm: pacAlgorithmQARMA5, Enabled: &enabled}, wantErr: true},
		{name: "address without algorithm", keys: pacKeys{Version: pacKeysVersion, Address: &address}, wantErr: true},
		{name: "algorithm without address", keys: pacKeys{Version: pacKeysVersion, AddressAlgorithm: pacAlgorithmQARMA5}, wantErr: true},
		{name: "unknown algorithm", keys: pacKeys{Version: pacKeysVersion, Address: &address, AddressAlgorithm: "unknown"}, wantErr: true},
		{name: "implementation defined without CPU", keys: pacKeys{Version: pacKeysVersion, Address: &address, AddressAlgorithm: pacAlgorithmIMPDEF}, wantErr: true},
		{name: "CPU without implementation defined", keys: pacKeys{Version: pacKeysVersion, Address: &address, AddressAlgorithm: pacAlgorithmQARMA5, CPU: &cpu}, wantErr: true},
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
			if got.AddressAlgorithm != test.keys.AddressAlgorithm {
				t.Errorf("AddressAlgorithm = %q, want %q", got.AddressAlgorithm, test.keys.AddressAlgorithm)
			}
			if got.GenericAlgorithm != test.keys.GenericAlgorithm {
				t.Errorf("GenericAlgorithm = %q, want %q", got.GenericAlgorithm, test.keys.GenericAlgorithm)
			}
			if (got.CPU == nil) != (test.keys.CPU == nil) || (got.CPU != nil && *got.CPU != *test.keys.CPU) {
				t.Errorf("CPU = %v, want %v", got.CPU, test.keys.CPU)
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
	cpu := pacCPU{Implementer: 1, Part: 2}
	otherCPU := pacCPU{Implementer: 1, Part: 3}
	for _, test := range []struct {
		name    string
		keys    pacKeys
		host    hostPAC
		wantErr bool
	}{
		{name: "all supported", keys: pacKeys{Address: address, Generic: generic, AddressAlgorithm: pacAlgorithmQARMA5, GenericAlgorithm: pacAlgorithmQARMA3}, host: hostPAC{address: true, generic: true, addressAlgorithm: pacAlgorithmQARMA5, genericAlgorithm: pacAlgorithmQARMA3}},
		{name: "no host support", keys: pacKeys{Address: address, Generic: generic}, host: hostPAC{}, wantErr: true},
		{name: "no generic support", keys: pacKeys{Address: address, Generic: generic}, host: hostPAC{address: true}, wantErr: true},
		{name: "no address support", keys: pacKeys{Address: address}, host: hostPAC{generic: true}, wantErr: true},
		{name: "address keys only", keys: pacKeys{Address: address, AddressAlgorithm: pacAlgorithmQARMA5}, host: hostPAC{address: true, addressAlgorithm: pacAlgorithmQARMA5}},
		{name: "address algorithm mismatch", keys: pacKeys{Address: address, AddressAlgorithm: pacAlgorithmQARMA5}, host: hostPAC{address: true, addressAlgorithm: pacAlgorithmQARMA3}, wantErr: true},
		{name: "generic algorithm mismatch", keys: pacKeys{Generic: generic, GenericAlgorithm: pacAlgorithmQARMA5}, host: hostPAC{generic: true, genericAlgorithm: pacAlgorithmIMPDEF}, wantErr: true},
		{name: "implementation defined same CPU", keys: pacKeys{Address: address, AddressAlgorithm: pacAlgorithmIMPDEF, CPU: &cpu}, host: hostPAC{address: true, addressAlgorithm: pacAlgorithmIMPDEF, cpu: cpu}},
		{name: "implementation defined different CPU", keys: pacKeys{Address: address, AddressAlgorithm: pacAlgorithmIMPDEF, CPU: &cpu}, host: hostPAC{address: true, addressAlgorithm: pacAlgorithmIMPDEF, cpu: otherCPU}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.keys.checkHost(test.host); (err != nil) != test.wantErr {
				t.Errorf("checkHost(%+v) error = %v, want error %t", test.host, err, test.wantErr)
			}
		})
	}
}

func TestPACAlgorithmFromFields(t *testing.T) {
	for _, test := range []struct {
		name                   string
		qarma3, qarma5, impdef uint64
		want                   pacAlgorithm
	}{
		{name: "none"},
		{name: "QARMA3", qarma3: 1, want: pacAlgorithmQARMA3},
		{name: "QARMA5 feature level", qarma5: 5, want: pacAlgorithmQARMA5},
		{name: "implementation defined", impdef: 1, want: pacAlgorithmIMPDEF},
		{name: "ambiguous", qarma3: 1, qarma5: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pacAlgorithmFromFields(test.qarma3, test.qarma5, test.impdef); got != test.want {
				t.Errorf("pacAlgorithmFromFields(%d, %d, %d) = %q, want %q", test.qarma3, test.qarma5, test.impdef, got, test.want)
			}
		})
	}
}
