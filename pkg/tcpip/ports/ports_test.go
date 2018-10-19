// Copyright 2018 Google LLC
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

package ports

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

const (
	fakeTransNumber   tcpip.TransportProtocolNumber = 1
	fakeNetworkNumber tcpip.NetworkProtocolNumber   = 2

	fakeIPAddress  = tcpip.Address("\x08\x08\x08\x08")
	fakeIPAddress1 = tcpip.Address("\x08\x08\x08\x09")
)

func TestPortReservation(t *testing.T) {
	pm := NewPortManager()
	net := []tcpip.NetworkProtocolNumber{fakeNetworkNumber}

	for _, test := range []struct {
		port uint16
		ip   tcpip.Address
		want *tcpip.Error
	}{
		{
			port: 80,
			ip:   fakeIPAddress,
			want: nil,
		},
		{
			port: 80,
			ip:   fakeIPAddress1,
			want: nil,
		},
		{
			/* N.B. Order of tests matters! */
			port: 80,
			ip:   anyIPAddress,
			want: tcpip.ErrPortInUse,
		},
		{
			port: 22,
			ip:   anyIPAddress,
			want: nil,
		},
		{
			port: 22,
			ip:   fakeIPAddress,
			want: tcpip.ErrPortInUse,
		},
		{
			port: 0,
			ip:   fakeIPAddress,
			want: nil,
		},
		{
			port: 0,
			ip:   fakeIPAddress,
			want: nil,
		},
	} {
		gotPort, err := pm.ReservePort(net, fakeTransNumber, test.ip, test.port)
		if err != test.want {
			t.Fatalf("ReservePort(.., .., %s, %d) = %v, want %v", test.ip, test.port, err, test.want)
		}
		if test.port == 0 && (gotPort == 0 || gotPort < FirstEphemeral) {
			t.Fatalf("ReservePort(.., .., .., 0) = %d, want port number >= %d to be picked", gotPort, FirstEphemeral)
		}
	}

	// Release port 22 from any IP address, then try to reserve fake IP
	// address on 22.
	pm.ReleasePort(net, fakeTransNumber, anyIPAddress, 22)

	if port, err := pm.ReservePort(net, fakeTransNumber, fakeIPAddress, 22); port != 22 || err != nil {
		t.Fatalf("ReservePort(.., .., .., %d) = (port %d, err %v), want (22, nil); failed to reserve port after it should have been released", 22, port, err)
	}
}

func TestPickEphemeralPort(t *testing.T) {
	pm := NewPortManager()
	customErr := &tcpip.Error{}
	for _, test := range []struct {
		name     string
		f        func(port uint16) (bool, *tcpip.Error)
		wantErr  *tcpip.Error
		wantPort uint16
	}{
		{
			name: "no-port-available",
			f: func(port uint16) (bool, *tcpip.Error) {
				return false, nil
			},
			wantErr: tcpip.ErrNoPortAvailable,
		},
		{
			name: "port-tester-error",
			f: func(port uint16) (bool, *tcpip.Error) {
				return false, customErr
			},
			wantErr: customErr,
		},
		{
			name: "only-port-16042-available",
			f: func(port uint16) (bool, *tcpip.Error) {
				if port == FirstEphemeral+42 {
					return true, nil
				}
				return false, nil
			},
			wantPort: FirstEphemeral + 42,
		},
		{
			name: "only-port-under-16000-available",
			f: func(port uint16) (bool, *tcpip.Error) {
				if port < FirstEphemeral {
					return true, nil
				}
				return false, nil
			},
			wantErr: tcpip.ErrNoPortAvailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if port, err := pm.PickEphemeralPort(test.f); port != test.wantPort || err != test.wantErr {
				t.Errorf("PickEphemeralPort(..) = (port %d, err %v); want (port %d, err %v)", port, err, test.wantPort, test.wantErr)
			}
		})
	}
}
