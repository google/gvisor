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
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

// pacKeysVersion is the version of the pacKeys encoding.
const pacKeysVersion = 1

// pacAlgorithm identifies a pointer authentication signing algorithm.
type pacAlgorithm string

const (
	pacAlgorithmQARMA5 pacAlgorithm = "qarma5"
	pacAlgorithmQARMA3 pacAlgorithm = "qarma3"
	pacAlgorithmIMPDEF pacAlgorithm = "implementation-defined"
)

// pacCPU identifies a CPU implementation. It is used to conservatively
// determine compatibility for implementation-defined PAC algorithms.
type pacCPU struct {
	Implementer  uint8  `json:"implementer"`
	Architecture uint8  `json:"architecture"`
	Variant      uint8  `json:"variant"`
	Part         uint16 `json:"part"`
	Revision     uint8  `json:"revision"`
}

// pacKeys holds ARM64 pointer authentication state of a stub process.
//
// All stub processes are cloned from the source subprocess, and a clone
// inherits the keys and enabled keys of the thread that creates it, so the
// source's ptrace thread holds this state for every stub process.
type pacKeys struct {
	// Version is pacKeysVersion.
	Version int `json:"version"`

	// Address holds the APIA, APIB, APDA and APDB keys in the layout of
	// struct user_pac_address_keys (NT_ARM_PACA_KEYS). It is nil if the host
	// does not support address authentication.
	Address *[8]uint64 `json:"address,omitempty"`

	// Generic holds the APGA key in the layout of struct user_pac_generic_keys
	// (NT_ARM_PACG_KEYS). It is nil if the host does not support generic
	// authentication.
	Generic *[2]uint64 `json:"generic,omitempty"`

	// AddressAlgorithm is the algorithm used with Address.
	AddressAlgorithm pacAlgorithm `json:"address_algorithm,omitempty"`

	// GenericAlgorithm is the algorithm used with Generic.
	GenericAlgorithm pacAlgorithm `json:"generic_algorithm,omitempty"`

	// CPU identifies the CPU on which implementation-defined algorithms were
	// used. It is omitted for architected algorithms.
	CPU *pacCPU `json:"cpu,omitempty"`

	// Enabled holds the enabled address keys as a PR_PAC_* mask
	// (NT_ARM_PAC_ENABLED_KEYS). It is nil if the host kernel does not report
	// them, in which case all keys are enabled.
	Enabled *uint64 `json:"enabled,omitempty"`
}

// hostPAC describes which pointer authentication keys the host supports.
type hostPAC struct {
	address          bool
	generic          bool
	addressAlgorithm pacAlgorithm
	genericAlgorithm pacAlgorithm
	cpu              pacCPU
}

// checkHost returns an error if the host cannot install keys.
func (keys *pacKeys) checkHost(host hostPAC) error {
	if keys.Address != nil && !host.address {
		return fmt.Errorf("checkpoint has ARM64 pointer authentication address keys, but the host does not support address authentication")
	}
	if keys.Generic != nil && !host.generic {
		return fmt.Errorf("checkpoint has an ARM64 pointer authentication generic key, but the host does not support generic authentication")
	}
	if keys.Address != nil && keys.AddressAlgorithm != host.addressAlgorithm {
		return fmt.Errorf("checkpoint uses ARM64 address pointer authentication algorithm %q, but the host uses %q", keys.AddressAlgorithm, host.addressAlgorithm)
	}
	if keys.Generic != nil && keys.GenericAlgorithm != host.genericAlgorithm {
		return fmt.Errorf("checkpoint uses ARM64 generic pointer authentication algorithm %q, but the host uses %q", keys.GenericAlgorithm, host.genericAlgorithm)
	}
	if keys.CPU != nil && *keys.CPU != host.cpu {
		return fmt.Errorf("checkpoint uses an implementation-defined ARM64 pointer authentication algorithm on CPU %+v, but the host CPU is %+v", *keys.CPU, host.cpu)
	}
	return nil
}

func validPACAlgorithm(algorithm pacAlgorithm) bool {
	switch algorithm {
	case pacAlgorithmQARMA5, pacAlgorithmQARMA3, pacAlgorithmIMPDEF:
		return true
	default:
		return false
	}
}

// pacAlgorithmFromFields identifies an algorithm from the mutually exclusive
// QARMA3, QARMA5, and implementation-defined ID register fields.
func pacAlgorithmFromFields(qarma3, qarma5, impdef uint64) pacAlgorithm {
	var algorithm pacAlgorithm
	for _, field := range []struct {
		value     uint64
		algorithm pacAlgorithm
	}{
		{qarma3, pacAlgorithmQARMA3},
		{qarma5, pacAlgorithmQARMA5},
		{impdef, pacAlgorithmIMPDEF},
	} {
		if field.value == 0 {
			continue
		}
		if algorithm != "" {
			return ""
		}
		algorithm = field.algorithm
	}
	return algorithm
}

// decodePACKeys decodes keys encoded by SavePACKeys.
func decodePACKeys(data []byte) (*pacKeys, error) {
	var keys pacKeys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("decoding pointer authentication keys: %w", err)
	}
	if keys.Version != pacKeysVersion {
		return nil, fmt.Errorf("pointer authentication keys have version %d, want %d", keys.Version, pacKeysVersion)
	}
	if keys.Address == nil && keys.Generic == nil {
		return nil, fmt.Errorf("pointer authentication keys are empty")
	}
	if keys.Enabled != nil && keys.Address == nil {
		return nil, fmt.Errorf("pointer authentication enabled keys are set without address keys")
	}
	if (keys.Address != nil) != validPACAlgorithm(keys.AddressAlgorithm) {
		return nil, fmt.Errorf("pointer authentication address keys and a valid address algorithm must both be present")
	}
	if (keys.Generic != nil) != validPACAlgorithm(keys.GenericAlgorithm) {
		return nil, fmt.Errorf("pointer authentication generic key and a valid generic algorithm must both be present")
	}
	impdef := keys.AddressAlgorithm == pacAlgorithmIMPDEF || keys.GenericAlgorithm == pacAlgorithmIMPDEF
	if impdef != (keys.CPU != nil) {
		return nil, fmt.Errorf("pointer authentication CPU identity must be present exactly when an algorithm is implementation-defined")
	}
	return &keys, nil
}

// requestPACKeys asks a subprocess's request goroutine to read or write the
// pointer authentication state of its ptrace thread.
type requestPACKeys struct {
	keys *pacKeys
	set  bool
	done chan error
}

// accessPACKeys reads the fields of keys that are non-nil from, or with set
// writes them to, the ptrace thread of s.
func (s *subprocess) accessPACKeys(keys *pacKeys, set bool) error {
	r := requestPACKeys{keys: keys, set: set, done: make(chan error, 1)}
	s.requests <- r
	return <-r.done
}

// hostPAC returns which pointer authentication keys p can use.
func (p *Systrap) hostPAC() hostPAC {
	if p.noPACForTest {
		return hostPAC{}
	}
	return hostPACSupport()
}

// SavePACKeys returns the ARM64 pointer authentication state of the stub
// processes, encoded for checkpoint metadata. It returns nil if the host does
// not support pointer authentication.
func (p *Systrap) SavePACKeys() ([]byte, error) {
	host := p.hostPAC()
	if !host.address && !host.generic {
		return nil, nil
	}
	keys := pacKeys{
		Version:          pacKeysVersion,
		AddressAlgorithm: host.addressAlgorithm,
		GenericAlgorithm: host.genericAlgorithm,
	}
	if host.address {
		if !validPACAlgorithm(host.addressAlgorithm) {
			return nil, fmt.Errorf("determining host ARM64 address pointer authentication algorithm")
		}
		keys.Address = new([8]uint64)
	}
	if host.generic {
		if !validPACAlgorithm(host.genericAlgorithm) {
			return nil, fmt.Errorf("determining host ARM64 generic pointer authentication algorithm")
		}
		keys.Generic = new([2]uint64)
	}
	if host.addressAlgorithm == pacAlgorithmIMPDEF || host.genericAlgorithm == pacAlgorithmIMPDEF {
		keys.CPU = &host.cpu
	}
	if err := globalPool.source.accessPACKeys(&keys, false /* set */); err != nil {
		return nil, fmt.Errorf("reading pointer authentication keys: %w", err)
	}
	if host.address {
		// NT_ARM_PAC_ENABLED_KEYS is only available since Linux 5.13. Without it
		// the enabled keys cannot be changed, so all keys are enabled.
		enabled := pacKeys{Enabled: new(uint64)}
		if err := globalPool.source.accessPACKeys(&enabled, false /* set */); err == nil {
			keys.Enabled = enabled.Enabled
		} else if !errors.Is(err, unix.EINVAL) {
			return nil, fmt.Errorf("reading pointer authentication enabled keys: %w", err)
		}
	}
	return json.Marshal(&keys)
}

// RestorePACKeys installs state saved by SavePACKeys on the source subprocess,
// so that stub processes created afterwards use it. It must be called before
// any other stub process is created.
func (p *Systrap) RestorePACKeys(data []byte) error {
	keys, err := decodePACKeys(data)
	if err != nil {
		return err
	}
	if err := keys.checkHost(p.hostPAC()); err != nil {
		return err
	}
	if err := globalPool.source.accessPACKeys(keys, true /* set */); err != nil {
		return fmt.Errorf("installing pointer authentication keys: %w", err)
	}
	return nil
}

// DisablePACKeys disables pointer authentication with the address keys for
// stub processes created afterwards, so that pointer authentication
// instructions behave as on a host without it. It is used when restoring a
// checkpoint without keys, which was taken where the application did not sign
// pointers: its return addresses are unsigned, and authenticating them with
// enabled keys would fail. It must be called before any other stub process is
// created.
func (p *Systrap) DisablePACKeys() error {
	if !hostPACSupport().address {
		return nil
	}
	keys := pacKeys{Enabled: new(uint64)}
	if err := globalPool.source.accessPACKeys(&keys, true /* set */); err != nil {
		return fmt.Errorf("disabling pointer authentication keys: %w", err)
	}
	return nil
}

// DisablePACForTest makes p behave as on a host without pointer
// authentication: address keys are disabled and checkpoints carry no keys.
// It must be called before any other stub process is created.
func (p *Systrap) DisablePACForTest() error {
	p.noPACForTest = true
	log.Warningf("Pointer authentication disabled for testing")
	return p.DisablePACKeys()
}
