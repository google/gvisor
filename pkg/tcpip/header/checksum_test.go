// Copyright 2019 The gVisor Authors.
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

// Package header provides the implementation of the encoding and decoding of
// network protocol headers.
package header_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestChecksumer(t *testing.T) {
	testCases := []struct {
		name string
		data [][]byte
		want uint16
	}{
		{
			name: "empty",
			want: 0,
		},
		{
			name: "OneOddView",
			data: [][]byte{
				[]byte{1, 9, 0, 5, 4},
			},
			want: 1294,
		},
		{
			name: "TwoOddViews",
			data: [][]byte{
				[]byte{1, 9, 0, 5, 4},
				[]byte{4, 3, 7, 1, 2, 123},
			},
			want: 33819,
		},
		{
			name: "OneEvenView",
			data: [][]byte{
				[]byte{1, 9, 0, 5},
			},
			want: 270,
		},
		{
			name: "TwoEvenViews",
			data: [][]byte{
				buffer.NewViewFromBytes([]byte{98, 1, 9, 0}),
				buffer.NewViewFromBytes([]byte{9, 0, 5, 4}),
			},
			want: 30981,
		},
		{
			name: "ThreeViews",
			data: [][]byte{
				[]byte{77, 11, 33, 0, 55, 44},
				[]byte{98, 1, 9, 0, 5, 4},
				[]byte{4, 3, 7, 1, 2, 123, 99},
			},
			want: 34236,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var all bytes.Buffer
			var c header.Checksumer
			for _, b := range tc.data {
				c.Add(b)
				// Append to the buffer. We will check the checksum as a whole later.
				if _, err := all.Write(b); err != nil {
					t.Fatalf("all.Write(b) = _, %s; want _, nil", err)
				}
			}
			if got, want := c.Checksum(), tc.want; got != want {
				t.Errorf("c.Checksum() = %d, want %d", got, want)
			}
			if got, want := header.Checksum(all.Bytes(), 0 /* initial */), tc.want; got != want {
				t.Errorf("Checksum(flatten tc.data) = %d, want %d", got, want)
			}
		})
	}
}

func TestChecksum(t *testing.T) {
	var bufSizes = []int{0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 257, 1023, 1024}
	type testCase struct {
		buf      []byte
		initial  uint16
		csumOrig uint16
		csumNew  uint16
	}
	testCases := make([]testCase, 100000)
	// Ensure same buffer generation for test consistency.
	rnd := rand.New(rand.NewSource(42))
	for i := range testCases {
		testCases[i].buf = make([]byte, bufSizes[i%len(bufSizes)])
		testCases[i].initial = uint16(rnd.Intn(65536))
		rnd.Read(testCases[i].buf)
	}

	for i := range testCases {
		testCases[i].csumOrig = header.ChecksumOld(testCases[i].buf, testCases[i].initial)
		testCases[i].csumNew = header.Checksum(testCases[i].buf, testCases[i].initial)
		if got, want := testCases[i].csumNew, testCases[i].csumOrig; got != want {
			t.Fatalf("new checksum for (buf = %x, initial = %d) does not match old got: %d, want: %d", testCases[i].buf, testCases[i].initial, got, want)
		}
	}
}

func BenchmarkChecksum(b *testing.B) {
	var bufSizes = []int{64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32767, 32768, 65535, 65536}

	checkSumImpls := []struct {
		fn   func([]byte, uint16) uint16
		name string
	}{
		{header.ChecksumOld, fmt.Sprintf("checksum_old")},
		{header.Checksum, fmt.Sprintf("checksum")},
	}

	for _, csumImpl := range checkSumImpls {
		// Ensure same buffer generation for test consistency.
		rnd := rand.New(rand.NewSource(42))
		for _, bufSz := range bufSizes {
			b.Run(fmt.Sprintf("%s_%d", csumImpl.name, bufSz), func(b *testing.B) {
				tc := struct {
					buf     []byte
					initial uint16
					csum    uint16
				}{
					buf:     make([]byte, bufSz),
					initial: uint16(rnd.Intn(65536)),
				}
				rnd.Read(tc.buf)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					tc.csum = csumImpl.fn(tc.buf, tc.initial)
				}
			})
		}
	}
}

func testICMPChecksum(t *testing.T, headerChecksum func() uint16, icmpChecksum func() uint16, want uint16, pktStr string) {
	// icmpChecksum should not do any modifications of the header to
	// calculate its checksum. Let's call it from a few go-routines and the
	// race detector will trigger a warning if there are any concurrent
	// read/write accesses.

	const concurrency = 5
	start := make(chan int)
	ready := make(chan bool, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	defer wg.Wait()

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()

			ready <- true
			<-start

			if got := headerChecksum(); want != got {
				t.Errorf("new checksum for %s does not match old got: %x, want: %x", pktStr, got, want)
			}
			if got := icmpChecksum(); want != got {
				t.Errorf("new checksum for %s does not match old got: %x, want: %x", pktStr, got, want)
			}
		}()
	}
	for i := 0; i < concurrency; i++ {
		<-ready
	}
	close(start)
}

func TestICMPv4Checksum(t *testing.T) {
	rnd := rand.New(rand.NewSource(42))

	h := header.ICMPv4(make([]byte, header.ICMPv4MinimumSize))
	if _, err := rnd.Read(h); err != nil {
		t.Fatalf("rnd.Read failed: %v", err)
	}
	h.SetChecksum(0)

	buf := make([]byte, 13)
	if _, err := rnd.Read(buf); err != nil {
		t.Fatalf("rnd.Read failed: %v", err)
	}
	vv := buffer.NewVectorisedView(len(buf), []buffer.View{
		buffer.NewViewFromBytes(buf[:5]),
		buffer.NewViewFromBytes(buf[5:]),
	})

	want := header.Checksum(vv.ToView(), 0)
	want = ^header.Checksum(h, want)
	h.SetChecksum(want)

	testICMPChecksum(t, h.Checksum, func() uint16 {
		return header.ICMPv4Checksum(h, header.ChecksumVV(vv, 0))
	}, want, fmt.Sprintf("header: {% x} data {% x}", h, vv.ToView()))
}

func TestICMPv6Checksum(t *testing.T) {
	rnd := rand.New(rand.NewSource(42))

	h := header.ICMPv6(make([]byte, header.ICMPv6MinimumSize))
	if _, err := rnd.Read(h); err != nil {
		t.Fatalf("rnd.Read failed: %v", err)
	}
	h.SetChecksum(0)

	buf := make([]byte, 13)
	if _, err := rnd.Read(buf); err != nil {
		t.Fatalf("rnd.Read failed: %v", err)
	}
	vv := buffer.NewVectorisedView(len(buf), []buffer.View{
		buffer.NewViewFromBytes(buf[:7]),
		buffer.NewViewFromBytes(buf[7:10]),
		buffer.NewViewFromBytes(buf[10:]),
	})

	dst := header.IPv6Loopback
	src := header.IPv6Loopback

	want := header.PseudoHeaderChecksum(header.ICMPv6ProtocolNumber, src, dst, uint16(len(h)+vv.Size()))
	want = header.Checksum(vv.ToView(), want)
	want = ^header.Checksum(h, want)
	h.SetChecksum(want)

	testICMPChecksum(t, h.Checksum, func() uint16 {
		return header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      h,
			Src:         src,
			Dst:         dst,
			PayloadCsum: header.ChecksumVV(vv, 0),
			PayloadLen:  vv.Size(),
		})
	}, want, fmt.Sprintf("header: {% x} data {% x}", h, vv.ToView()))
}

func randomAddress(size int) tcpip.Address {
	s := make([]byte, size)
	for i := 0; i < size; i++ {
		s[i] = byte(rand.Uint32())
	}
	return tcpip.Address(s)
}

func TestChecksummableNetworkUpdateAddress(t *testing.T) {
	tests := []struct {
		name   string
		update func(header.IPv4, tcpip.Address)
	}{
		{
			name:   "SetSourceAddressWithChecksumUpdate",
			update: header.IPv4.SetSourceAddressWithChecksumUpdate,
		},
		{
			name:   "SetDestinationAddressWithChecksumUpdate",
			update: header.IPv4.SetDestinationAddressWithChecksumUpdate,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for i := 0; i < 1000; i++ {
				var origBytes [header.IPv4MinimumSize]byte
				header.IPv4(origBytes[:]).Encode(&header.IPv4Fields{
					TOS:            1,
					TotalLength:    header.IPv4MinimumSize,
					ID:             2,
					Flags:          3,
					FragmentOffset: 4,
					TTL:            5,
					Protocol:       6,
					Checksum:       0,
					SrcAddr:        randomAddress(header.IPv4AddressSize),
					DstAddr:        randomAddress(header.IPv4AddressSize),
				})

				addr := randomAddress(header.IPv4AddressSize)

				bytesCopy := origBytes
				h := header.IPv4(bytesCopy[:])
				origXSum := h.CalculateChecksum()
				h.SetChecksum(^origXSum)

				test.update(h, addr)
				got := ^h.Checksum()
				h.SetChecksum(0)
				want := h.CalculateChecksum()
				if got != want {
					t.Errorf("got h.Checksum() = 0x%x, want = 0x%x; originalBytes = 0x%x, new addr = %s", got, want, origBytes, addr)
				}
			}
		})
	}
}

func TestChecksummableTransportUpdatePort(t *testing.T) {
	// The fields in the pseudo header is not tested here so we just use 0.
	const pseudoHeaderXSum = 0

	tests := []struct {
		name         string
		transportHdr func(_, _ uint16) (header.ChecksummableTransport, func(uint16) uint16)
		proto        tcpip.TransportProtocolNumber
	}{
		{
			name: "TCP",
			transportHdr: func(src, dst uint16) (header.ChecksummableTransport, func(uint16) uint16) {
				h := header.TCP(make([]byte, header.TCPMinimumSize))
				h.Encode(&header.TCPFields{
					SrcPort:       src,
					DstPort:       dst,
					SeqNum:        1,
					AckNum:        2,
					DataOffset:    header.TCPMinimumSize,
					Flags:         3,
					WindowSize:    4,
					Checksum:      0,
					UrgentPointer: 5,
				})
				h.SetChecksum(^h.CalculateChecksum(pseudoHeaderXSum))
				return h, h.CalculateChecksum
			},
			proto: header.TCPProtocolNumber,
		},
		{
			name: "UDP",
			transportHdr: func(src, dst uint16) (header.ChecksummableTransport, func(uint16) uint16) {
				h := header.UDP(make([]byte, header.UDPMinimumSize))
				h.Encode(&header.UDPFields{
					SrcPort:  src,
					DstPort:  dst,
					Length:   0,
					Checksum: 0,
				})
				h.SetChecksum(^h.CalculateChecksum(pseudoHeaderXSum))
				return h, h.CalculateChecksum
			},
			proto: header.UDPProtocolNumber,
		},
	}

	for i := 0; i < 1000; i++ {
		origSrcPort := uint16(rand.Uint32())
		origDstPort := uint16(rand.Uint32())
		newPort := uint16(rand.Uint32())

		t.Run(fmt.Sprintf("OrigSrcPort=%d,OrigDstPort=%d,NewPort=%d", origSrcPort, origDstPort, newPort), func(*testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					for _, subTest := range []struct {
						name   string
						update func(header.ChecksummableTransport)
					}{
						{
							name:   "Source port",
							update: func(h header.ChecksummableTransport) { h.SetSourcePortWithChecksumUpdate(newPort) },
						},
						{
							name:   "Destination port",
							update: func(h header.ChecksummableTransport) { h.SetDestinationPortWithChecksumUpdate(newPort) },
						},
					} {
						t.Run(subTest.name, func(t *testing.T) {
							h, calcXSum := test.transportHdr(origSrcPort, origDstPort)
							subTest.update(h)
							// TCP and UDP hold the 1s complement of the fully calculated
							// checksum.
							got := ^h.Checksum()
							h.SetChecksum(0)

							if want := calcXSum(pseudoHeaderXSum); got != want {
								h, _ := test.transportHdr(origSrcPort, origDstPort)
								t.Errorf("got Checksum() = 0x%x, want = 0x%x; originalBytes = %#v, new port = %d", got, want, h, newPort)
							}
						})
					}
				})
			}
		})
	}
}

func TestChecksummableTransportUpdatePseudoHeaderAddress(t *testing.T) {
	const addressSize = 6

	tests := []struct {
		name         string
		transportHdr func() header.ChecksummableTransport
		proto        tcpip.TransportProtocolNumber
	}{
		{
			name:         "TCP",
			transportHdr: func() header.ChecksummableTransport { return header.TCP(make([]byte, header.TCPMinimumSize)) },
			proto:        header.TCPProtocolNumber,
		},
		{
			name:         "UDP",
			transportHdr: func() header.ChecksummableTransport { return header.UDP(make([]byte, header.UDPMinimumSize)) },
			proto:        header.UDPProtocolNumber,
		},
	}

	for i := 0; i < 1000; i++ {
		permanent := randomAddress(addressSize)
		old := randomAddress(addressSize)
		new := randomAddress(addressSize)

		t.Run(fmt.Sprintf("Permanent=%q,Old=%q,New=%q", permanent, old, new), func(t *testing.T) {
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					for _, fullChecksum := range []bool{true, false} {
						t.Run(fmt.Sprintf("FullChecksum=%t", fullChecksum), func(t *testing.T) {
							initialXSum := header.PseudoHeaderChecksum(test.proto, permanent, old, 0)
							if fullChecksum {
								// TCP and UDP hold the 1s complement of the fully calculated
								// checksum.
								initialXSum = ^initialXSum
							}

							h := test.transportHdr()
							h.SetChecksum(initialXSum)
							h.UpdateChecksumPseudoHeaderAddress(old, new, fullChecksum)

							got := h.Checksum()
							if fullChecksum {
								got = ^got
							}
							if want := header.PseudoHeaderChecksum(test.proto, permanent, new, 0); got != want {
								t.Errorf("got Checksum() = 0x%x, want = 0x%x; h = %#v", got, want, h)
							}
						})
					}
				})
			}
		})
	}
}
