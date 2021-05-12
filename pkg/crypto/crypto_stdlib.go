// Copyright 2020 The gVisor Authors.
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

package crypto

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"math/big"
)

// EcdsaVerify verifies the signature in r, s of hash using ECDSA and the
// public key, pub. Its return value records whether the signature is valid.
func EcdsaVerify(pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) (bool, error) {
	return ecdsa.Verify(pub, hash, r, s), nil
}

// SumSha384 returns the SHA384 checksum of the data.
func SumSha384(data []byte) ([sha512.Size384]byte, error) {
	return sha512.Sum384(data), nil
}
