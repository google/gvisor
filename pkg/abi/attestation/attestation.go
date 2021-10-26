// Copyright 2021 The gVisor Authors.
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

// Package attestation includes definitions needed for gVisor attestation.
package attestation

// Attestation ioctls.
const (
	SIGN_ATTESTATION_REPORT = 0
)

// SizeOfQuoteInputData is the number of bytes in the input data of ioctl call
// to get quote.
const SizeOfQuoteInputData = 64

// SignReport is a struct that gets signed quote from input data. The
// serialized quote is copied to buf.
// size is an input that specifies the size of buf. When returned, it's updated
// to the size of quote.
type SignReport struct {
	data [64]byte
	size uint32
	buf  []byte
}
