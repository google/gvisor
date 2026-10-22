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

package auth

import (
	"math"
	"testing"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

const testKUID KUID = 1000

func TestKeyQuotaMaxKeys(t *testing.T) {
	q := NewKeyQuotas()
	q.MaxKeys.Store(2)
	for i := 0; i < 2; i++ {
		if err := q.charge(testKUID, 1, false); err != nil {
			t.Fatalf("charge %d: got %v, want nil", i, err)
		}
	}
	if err := q.charge(testKUID, 1, false); !linuxerr.Equals(linuxerr.EDQUOT, err) {
		t.Fatalf("charge over maxkeys: got %v, want EDQUOT", err)
	}
	if err := q.charge(testKUID+1, 1, false); err != nil {
		t.Errorf("charge for another user: got %v, want nil", err)
	}
	q.uncharge(testKUID, 1)
	if err := q.charge(testKUID, 1, false); err != nil {
		t.Errorf("charge after uncharge: got %v, want nil", err)
	}
}

func TestKeyQuotaMaxBytes(t *testing.T) {
	q := NewKeyQuotas()
	q.MaxBytes.Store(10)
	if err := q.charge(testKUID, 10, false); err != nil {
		t.Fatalf("charge up to maxbytes: got %v, want nil", err)
	}
	if err := q.charge(testKUID, 1, false); !linuxerr.Equals(linuxerr.EDQUOT, err) {
		t.Errorf("charge over maxbytes: got %v, want EDQUOT", err)
	}
}

func TestKeyQuotaBytesOverflow(t *testing.T) {
	q := NewKeyQuotas()
	q.MaxBytes.Store(math.MaxInt32)
	if err := q.charge(testKUID, math.MaxInt32, false); err != nil {
		t.Fatalf("charge: got %v, want nil", err)
	}
	if err := q.charge(testKUID, math.MaxUint32, false); !linuxerr.Equals(linuxerr.EDQUOT, err) {
		t.Errorf("charge that wraps nbytes: got %v, want EDQUOT", err)
	}
}

func TestKeyQuotaOverrun(t *testing.T) {
	q := NewKeyQuotas()
	q.MaxKeys.Store(1)
	if err := q.charge(testKUID, 1, false); err != nil {
		t.Fatalf("charge: got %v, want nil", err)
	}
	if err := q.charge(testKUID, 1, true); err != nil {
		t.Fatalf("overrun charge: got %v, want nil", err)
	}
	// The overrun key still counts against the user.
	q.uncharge(testKUID, 1)
	if err := q.charge(testKUID, 1, false); !linuxerr.Equals(linuxerr.EDQUOT, err) {
		t.Errorf("charge with overrun key held: got %v, want EDQUOT", err)
	}
}

func TestKeyQuotaRootLimits(t *testing.T) {
	q := NewKeyQuotas()
	q.MaxKeys.Store(1)
	q.MaxBytes.Store(1)
	q.RootMaxKeys.Store(2)
	for i := 0; i < 2; i++ {
		if err := q.charge(RootKUID, 2, false); err != nil {
			t.Fatalf("root charge %d: got %v, want nil", i, err)
		}
	}
	if err := q.charge(RootKUID, 2, false); !linuxerr.Equals(linuxerr.EDQUOT, err) {
		t.Errorf("root charge over root_maxkeys: got %v, want EDQUOT", err)
	}
}

func TestKeyQuotaUserRemovedWhenUnused(t *testing.T) {
	q := NewKeyQuotas()
	if err := q.charge(testKUID, 3, false); err != nil {
		t.Fatalf("charge: got %v, want nil", err)
	}
	if err := q.charge(testKUID, 4, false); err != nil {
		t.Fatalf("charge: got %v, want nil", err)
	}
	q.uncharge(testKUID, 3)
	q.mu.Lock()
	u, ok := q.users[testKUID]
	q.mu.Unlock()
	if !ok || u.nkeys != 1 || u.nbytes != 4 {
		t.Fatalf("usage after one uncharge: got %+v (present %t), want {nkeys:1 nbytes:4}", u, ok)
	}
	q.uncharge(testKUID, 4)
	q.mu.Lock()
	_, ok = q.users[testKUID]
	q.mu.Unlock()
	if ok {
		t.Errorf("user with no usage still has an entry")
	}
}

func TestKeyQuotaUnchargeWithoutChargePanics(t *testing.T) {
	q := NewKeyQuotas()
	defer func() {
		if recover() == nil {
			t.Errorf("uncharge without charge did not panic")
		}
	}()
	q.uncharge(testKUID, 1)
}
