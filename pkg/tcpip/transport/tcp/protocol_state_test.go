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

package tcp

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestProtocolSecretsHaveNosaveTag is a structural assertion that the
// seqnumSecret and tsOffsetSecret fields on the protocol struct carry the
// state:"nosave" tag. Removing the tag would silently restore stale
// secrets across checkpoint, defeating afterLoad re-seeding.
func TestProtocolSecretsHaveNosaveTag(t *testing.T) {
	var p protocol
	typ := reflect.TypeOf(p)
	for _, name := range []string{"seqnumSecret", "tsOffsetSecret"} {
		f, ok := typ.FieldByName(name)
		if !ok {
			t.Fatalf("field %s not found on protocol", name)
		}
		if got, want := f.Tag.Get("state"), "nosave"; got != want {
			t.Errorf("field %s state-tag = %q, want %q", name, got, want)
		}
	}
}

// TestProtocolAfterLoadRegeneratesSecrets verifies that calling afterLoad on
// a protocol whose secret fields are zero-valued (the post-restore state for
// nosave fields) repopulates them with fresh, non-zero bytes drawn from the
// stack secure RNG.
func TestProtocolAfterLoadRegeneratesSecrets(t *testing.T) {
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	defer s.Destroy()

	tp := s.TransportProtocolInstance(ProtocolNumber)
	p, ok := tp.(*protocol)
	if !ok {
		t.Fatalf("transport protocol instance = %T, want *protocol", tp)
	}

	var initialSeq, initialTS [16]byte
	copy(initialSeq[:], p.seqnumSecret[:])
	copy(initialTS[:], p.tsOffsetSecret[:])

	var zero [16]byte
	if bytes.Equal(initialSeq[:], zero[:]) {
		t.Fatalf("seqnumSecret was zero before afterLoad call (RNG init failed)")
	}
	if bytes.Equal(initialTS[:], zero[:]) {
		t.Fatalf("tsOffsetSecret was zero before afterLoad call (RNG init failed)")
	}

	// Simulate post-restore: stateify gives nosave fields their zero value.
	p.seqnumSecret = [16]byte{}
	p.tsOffsetSecret = [16]byte{}

	p.afterLoad(context.Background())

	if bytes.Equal(p.seqnumSecret[:], zero[:]) {
		t.Errorf("seqnumSecret zero after afterLoad: %x", p.seqnumSecret)
	}
	if bytes.Equal(p.tsOffsetSecret[:], zero[:]) {
		t.Errorf("tsOffsetSecret zero after afterLoad: %x", p.tsOffsetSecret)
	}
	if bytes.Equal(p.seqnumSecret[:], initialSeq[:]) {
		t.Errorf("seqnumSecret unchanged after afterLoad (collision unlikely with 16-byte secret): %x", p.seqnumSecret)
	}
	if bytes.Equal(p.tsOffsetSecret[:], initialTS[:]) {
		t.Errorf("tsOffsetSecret unchanged after afterLoad (collision unlikely with 16-byte secret): %x", p.tsOffsetSecret)
	}
}
