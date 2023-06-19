// Copyright 2023 The gVisor Authors.
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

package packet_test

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestWriteRaw(t *testing.T) {
	const nicID = 1

	tests := []struct {
		name      string
		len       int
		expectErr tcpip.Error
	}{
		{
			name:      "small",
			len:       header.EthernetMinimumSize - 1,
			expectErr: &tcpip.ErrMalformedHeader{},
		},
		{
			name:      "exact",
			len:       header.EthernetMinimumSize,
			expectErr: nil,
		},
		{
			name:      "bigger",
			len:       header.EthernetMinimumSize + 1,
			expectErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := stack.New(stack.Options{
				RawFactory:               &raw.EndpointFactory{},
				AllowPacketEndpointWrite: true,
				Clock:                    &faketime.NullClock{},
			})
			defer s.Destroy()

			chEP := channel.New(1, header.IPv6MinimumMTU, "")
			if err := s.CreateNIC(nicID, ethernet.New(chEP)); err != nil {
				t.Errorf("CreateNIC(%d, _) failed: %s", nicID, err)
			}

			var wq waiter.Queue
			ep, err := s.NewPacketEndpoint(false /* cooked */, 0 /* netProto */, &wq)
			if err != nil {
				t.Fatalf("s.NewPacketEndpoint(false, 0, _): %s", err)
			}
			defer ep.Close()

			bindAddr := tcpip.FullAddress{NIC: nicID}
			if err := ep.Bind(bindAddr); err != nil {
				t.Fatalf("ep.Bind(%#v): %s", bindAddr, err)
			}

			data := make([]byte, test.len)
			for i := range data {
				data[i] = byte(i)
			}

			var r bytes.Reader
			r.Reset(data)
			n, err := ep.Write(&r, tcpip.WriteOptions{})
			if diff := cmp.Diff(test.expectErr, err); diff != "" {
				t.Fatalf("ep.Write(..) mismatch:\n%s", diff)
			}
			if test.expectErr != nil {
				return
			}
			if want := int64(len(data)); n != want {
				t.Errorf("got ep.Write(..) = %d, want = %d", n, want)
			}
			pkt := chEP.Read()
			if pkt.IsNil() {
				t.Fatal("Packet wasn't written out")
			}
			defer pkt.DecRef()

			if diff := cmp.Diff(data, stack.PayloadSince(pkt.LinkHeader()).AsSlice()); diff != "" {
				t.Errorf("packet data mismatch:\n%s", diff)
			}
			if len := len(pkt.LinkHeader().Slice()); len != header.EthernetMinimumSize {
				t.Errorf("got len(pkt.LinkHeader().Slice()) = %d, want = %d", len, header.EthernetMinimumSize)
			}
		})
	}
}
