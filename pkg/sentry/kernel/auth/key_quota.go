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
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// Default key quotas. They match key_quota_maxkeys, key_quota_maxbytes,
// key_quota_root_maxkeys and key_quota_root_maxbytes in Linux's
// security/keys/key.c.
const (
	DefaultMaxKeys         = 200
	DefaultMaxKeyBytes     = 20000
	DefaultRootMaxKeys     = 1000000
	DefaultRootMaxKeyBytes = 25000000
)

// KeyQuotas accounts the keys owned by each user, across all user namespaces,
// against per-user limits. It corresponds to Linux's key_user records and the
// kernel.keys.* quota sysctls. The four limits are always in [1, INT_MAX].
//
// +stateify savable
type KeyQuotas struct {
	// MaxKeys and MaxBytes are the limits on the number of keys and on the
	// bytes charged to them for each user other than the root user
	// (/proc/sys/kernel/keys/maxkeys and maxbytes).
	MaxKeys  atomicbitops.Int32
	MaxBytes atomicbitops.Int32

	// RootMaxKeys and RootMaxBytes are the same limits for the root user
	// (/proc/sys/kernel/keys/root_maxkeys and root_maxbytes).
	RootMaxKeys  atomicbitops.Int32
	RootMaxBytes atomicbitops.Int32

	// mu protects users. It is a leaf lock.
	mu keyQuotaMutex `state:"nosave"`

	// users maps the owner of keys, as a KUID in the root user namespace, to
	// the usage charged to it. Users with no usage have no entry.
	//
	// +checklocks:mu
	users map[KUID]keyUser
}

// keyUser is the usage charged to one user.
//
// +stateify savable
type keyUser struct {
	// nkeys is the number of keys charged to the user (qnkeys in Linux).
	nkeys uint32

	// nbytes is the number of bytes charged to the user (qnbytes in Linux).
	nbytes uint32
}

// NewKeyQuotas returns a KeyQuotas with Linux's default limits and no usage.
func NewKeyQuotas() *KeyQuotas {
	return &KeyQuotas{
		MaxKeys:      atomicbitops.FromInt32(DefaultMaxKeys),
		MaxBytes:     atomicbitops.FromInt32(DefaultMaxKeyBytes),
		RootMaxKeys:  atomicbitops.FromInt32(DefaultRootMaxKeys),
		RootMaxBytes: atomicbitops.FromInt32(DefaultRootMaxKeyBytes),
	}
}

// charge charges one key with quotalen bytes to kuid. Like key_alloc, it
// returns EDQUOT if that would exceed the user's limits, unless overrun is
// set (KEY_ALLOC_QUOTA_OVERRUN), in which case the key is charged regardless.
//
// +checklocksexclude:q.mu
func (q *KeyQuotas) charge(kuid KUID, quotalen uint32, overrun bool) error {
	maxKeys, maxBytes := uint32(q.MaxKeys.Load()), uint32(q.MaxBytes.Load())
	if kuid == RootKUID {
		maxKeys, maxBytes = uint32(q.RootMaxKeys.Load()), uint32(q.RootMaxBytes.Load())
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	u := q.users[kuid]
	if !overrun {
		if u.nkeys+1 > maxKeys || u.nbytes+quotalen > maxBytes || u.nbytes+quotalen < u.nbytes {
			return linuxerr.EDQUOT
		}
	}
	u.nkeys++
	u.nbytes += quotalen
	if q.users == nil {
		q.users = make(map[KUID]keyUser)
	}
	q.users[kuid] = u
	return nil
}

// uncharge returns the quota charged by a successful call to charge.
//
// +checklocksexclude:q.mu
func (q *KeyQuotas) uncharge(kuid KUID, quotalen uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	u, ok := q.users[kuid]
	if !ok || u.nkeys == 0 || u.nbytes < quotalen {
		panic("KeyQuotas.uncharge of quota that was not charged")
	}
	u.nkeys--
	u.nbytes -= quotalen
	if u.nkeys == 0 && u.nbytes == 0 {
		delete(q.users, kuid)
	} else {
		q.users[kuid] = u
	}
}
