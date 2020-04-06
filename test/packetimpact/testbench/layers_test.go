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

package testbench

import "testing"

func TestLayerMatch(t *testing.T) {
	var nilPayload *Payload
	noPayload := &Payload{}
	emptyPayload := &Payload{Bytes: []byte{}}
	fullPayload := &Payload{Bytes: []byte{1, 2, 3}}
	emptyTCP := &TCP{SrcPort: Uint16(1234), LayerBase: LayerBase{nextLayer: emptyPayload}}
	fullTCP := &TCP{SrcPort: Uint16(1234), LayerBase: LayerBase{nextLayer: fullPayload}}
	for _, tt := range []struct {
		a, b Layer
		want bool
	}{
		{nilPayload, nilPayload, true},
		{nilPayload, noPayload, true},
		{nilPayload, emptyPayload, true},
		{nilPayload, fullPayload, true},
		{noPayload, noPayload, true},
		{noPayload, emptyPayload, true},
		{noPayload, fullPayload, true},
		{emptyPayload, emptyPayload, true},
		{emptyPayload, fullPayload, false},
		{fullPayload, fullPayload, true},
		{emptyTCP, fullTCP, true},
	} {
		if got := tt.a.match(tt.b); got != tt.want {
			t.Errorf("%s.match(%s) = %t, want %t", tt.a, tt.b, got, tt.want)
		}
		if got := tt.b.match(tt.a); got != tt.want {
			t.Errorf("%s.match(%s) = %t, want %t", tt.b, tt.a, got, tt.want)
		}
	}
}
