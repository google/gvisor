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

//go:build go1.1
// +build go1.1

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// EcdsaP384Sha384Verify verifies the signature in r, s of hash using ECDSA
// P384 + SHA 384 and the public key, pub. Its return value records whether
// the signature is valid.
func EcdsaP384Sha384Verify(pub *ecdsa.PublicKey, data []byte, r, s *big.Int) (bool, error) {
	if pub.Curve != elliptic.P384() {
		return false, fmt.Errorf("unsupported key curve: want P-384, got %v", pub.Curve)
	}
	digest := sha512.Sum384(data)
	return ecdsa.Verify(pub, digest[:], r, s), nil
}

// SumSha384 returns the SHA384 checksum of the data.
func SumSha384(data []byte) ([sha512.Size384]byte, error) {
	return sha512.Sum384(data), nil
}
