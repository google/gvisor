// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"bytes"
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestPacketHeaderPush(t *testing.T) {
	for _, test := range []struct {
		name      string
		reserved  int
		link      []byte
		network   []byte
		transport []byte
		data      []byte
	}{
		{
			name: "construct empty packet",
		},
		{
			name:     "construct link header only packet",
			reserved: 60,
			link:     makeView(10),
		},
		{
			name:     "construct link and network header only packet",
			reserved: 60,
			link:     makeView(10),
			network:  makeView(20),
		},
		{
			name:      "construct header only packet",
			reserved:  60,
			link:      makeView(10),
			network:   makeView(20),
			transport: makeView(30),
		},
		{
			name: "construct data only packet",
			data: makeView(40),
		},
		{
			name:      "construct L3 packet",
			reserved:  60,
			network:   makeView(20),
			transport: makeView(30),
			data:      makeView(40),
		},
		{
			name:      "construct L2 packet",
			reserved:  60,
			link:      makeView(10),
			network:   makeView(20),
			transport: makeView(30),
			data:      makeView(40),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pk := NewPacketBuffer(PacketBufferOptions{
				ReserveHeaderBytes: test.reserved,
				// Make a copy of data to make sure our truth data won't be taint by
				// PacketBuffer.
				Data: buffer.NewViewFromBytes(test.data).ToVectorisedView(),
			})

			allHdrSize := len(test.link) + len(test.network) + len(test.transport)

			// Check the initial values for packet.
			checkInitialPacketBuffer(t, pk, PacketBufferOptions{
				ReserveHeaderBytes: test.reserved,
				Data:               buffer.View(test.data).ToVectorisedView(),
			})

			// Push headers.
			if v := test.transport; len(v) > 0 {
				copy(pk.TransportHeader().Push(len(v)), v)
			}
			if v := test.network; len(v) > 0 {
				copy(pk.NetworkHeader().Push(len(v)), v)
			}
			if v := test.link; len(v) > 0 {
				copy(pk.LinkHeader().Push(len(v)), v)
			}

			// Check the after values for packet.
			if got, want := pk.ReservedHeaderBytes(), test.reserved; got != want {
				t.Errorf("After pk.ReservedHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.AvailableHeaderBytes(), test.reserved-allHdrSize; got != want {
				t.Errorf("After pk.AvailableHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.HeaderSize(), allHdrSize; got != want {
				t.Errorf("After pk.HeaderSize() = %d, want %d", got, want)
			}
			if got, want := pk.Size(), allHdrSize+len(test.data); got != want {
				t.Errorf("After pk.Size() = %d, want %d", got, want)
			}
			// Check the after state.
			checkPacketContents(t, "After ", pk, packetContents{
				link:      test.link,
				network:   test.network,
				transport: test.transport,
				data:      test.data,
			})
		})
	}
}

func TestPacketHeaderConsume(t *testing.T) {
	for _, test := range []struct {
		name      string
		data      []byte
		link      int
		network   int
		transport int
	}{
		{
			name:      "parse L2 packet",
			data:      concatViews(makeView(10), makeView(20), makeView(30), makeView(40)),
			link:      10,
			network:   20,
			transport: 30,
		},
		{
			name:      "parse L3 packet",
			data:      concatViews(makeView(20), makeView(30), makeView(40)),
			network:   20,
			transport: 30,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pk := NewPacketBuffer(PacketBufferOptions{
				// Make a copy of data to make sure our truth data won't be taint by
				// PacketBuffer.
				Data: buffer.NewViewFromBytes(test.data).ToVectorisedView(),
			})

			// Check the initial values for packet.
			checkInitialPacketBuffer(t, pk, PacketBufferOptions{
				Data: buffer.View(test.data).ToVectorisedView(),
			})

			// Consume headers.
			if size := test.link; size > 0 {
				if _, ok := pk.LinkHeader().Consume(size); !ok {
					t.Fatalf("pk.LinkHeader().Consume() = false, want true")
				}
			}
			if size := test.network; size > 0 {
				if _, ok := pk.NetworkHeader().Consume(size); !ok {
					t.Fatalf("pk.NetworkHeader().Consume() = false, want true")
				}
			}
			if size := test.transport; size > 0 {
				if _, ok := pk.TransportHeader().Consume(size); !ok {
					t.Fatalf("pk.TransportHeader().Consume() = false, want true")
				}
			}

			allHdrSize := test.link + test.network + test.transport

			// Check the after values for packet.
			if got, want := pk.ReservedHeaderBytes(), 0; got != want {
				t.Errorf("After pk.ReservedHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.AvailableHeaderBytes(), 0; got != want {
				t.Errorf("After pk.AvailableHeaderBytes() = %d, want %d", got, want)
			}
			if got, want := pk.HeaderSize(), allHdrSize; got != want {
				t.Errorf("After pk.HeaderSize() = %d, want %d", got, want)
			}
			if got, want := pk.Size(), len(test.data); got != want {
				t.Errorf("After pk.Size() = %d, want %d", got, want)
			}
			// Check the after state of pk.
			checkPacketContents(t, "After ", pk, packetContents{
				link:      test.data[:test.link],
				network:   test.data[test.link:][:test.network],
				transport: test.data[test.link+test.network:][:test.transport],
				data:      test.data[allHdrSize:],
			})
		})
	}
}

func TestPacketHeaderConsumeDataTooShort(t *testing.T) {
	data := makeView(10)

	pk := NewPacketBuffer(PacketBufferOptions{
		// Make a copy of data to make sure our truth data won't be taint by
		// PacketBuffer.
		Data: buffer.NewViewFromBytes(data).ToVectorisedView(),
	})

	// Consume should fail if pkt.Data is too short.
	if _, ok := pk.LinkHeader().Consume(11); ok {
		t.Fatalf("pk.LinkHeader().Consume() = _, true; want _, false")
	}
	if _, ok := pk.NetworkHeader().Consume(11); ok {
		t.Fatalf("pk.NetworkHeader().Consume() = _, true; want _, false")
	}
	if _, ok := pk.TransportHeader().Consume(11); ok {
		t.Fatalf("pk.TransportHeader().Consume() = _, true; want _, false")
	}

	// Check packet should look the same as initial packet.
	checkInitialPacketBuffer(t, pk, PacketBufferOptions{
		Data: buffer.View(data).ToVectorisedView(),
	})
}

// This is a very obscure use-case seen in the code that verifies packets
// before sending them out. It tries to parse the headers to verify.
// PacketHeader was initially not designed to mix Push() and Consume(), but it
// works and it's been relied upon. Include a test here.
func TestPacketHeaderPushConsumeMixed(t *testing.T) {
	link := makeView(10)
	network := makeView(20)
	data := makeView(30)

	initData := append([]byte(nil), network...)
	initData = append(initData, data...)
	pk := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: len(link),
		Data:               buffer.NewViewFromBytes(initData).ToVectorisedView(),
	})

	// 1. Consume network header
	gotNetwork, ok := pk.NetworkHeader().Consume(len(network))
	if !ok {
		t.Fatalf("pk.NetworkHeader().Consume(%d) = _, false; want _, true", len(network))
	}
	checkViewEqual(t, "gotNetwork", gotNetwork, network)

	// 2. Push link header
	copy(pk.LinkHeader().Push(len(link)), link)

	checkPacketContents(t, "" /* prefix */, pk, packetContents{
		link:    link,
		network: network,
		data:    data,
	})
}

func TestPacketHeaderPushCalledAtMostOnce(t *testing.T) {
	const headerSize = 10

	pk := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: headerSize * int(numHeaderType),
	})

	for _, h := range []PacketHeader{
		pk.TransportHeader(),
		pk.NetworkHeader(),
		pk.LinkHeader(),
	} {
		t.Run("PushedTwice/"+h.typ.String(), func(t *testing.T) {
			h.Push(headerSize)

			defer func() { recover() }()
			h.Push(headerSize)
			t.Fatal("Second push should have panicked")
		})
	}
}

func TestPacketHeaderConsumeCalledAtMostOnce(t *testing.T) {
	const headerSize = 10

	pk := NewPacketBuffer(PacketBufferOptions{
		Data: makeView(headerSize * int(numHeaderType)).ToVectorisedView(),
	})

	for _, h := range []PacketHeader{
		pk.LinkHeader(),
		pk.NetworkHeader(),
		pk.TransportHeader(),
	} {
		t.Run("ConsumedTwice/"+h.typ.String(), func(t *testing.T) {
			if _, ok := h.Consume(headerSize); !ok {
				t.Fatal("First consume should succeed")
			}

			defer func() { recover() }()
			h.Consume(headerSize)
			t.Fatal("Second consume should have panicked")
		})
	}
}

func TestPacketHeaderPushThenConsumePanics(t *testing.T) {
	const headerSize = 10

	pk := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: headerSize * int(numHeaderType),
	})

	for _, h := range []PacketHeader{
		pk.TransportHeader(),
		pk.NetworkHeader(),
		pk.LinkHeader(),
	} {
		t.Run(h.typ.String(), func(t *testing.T) {
			h.Push(headerSize)

			defer func() { recover() }()
			h.Consume(headerSize)
			t.Fatal("Consume should have panicked")
		})
	}
}

func TestPacketHeaderConsumeThenPushPanics(t *testing.T) {
	const headerSize = 10

	pk := NewPacketBuffer(PacketBufferOptions{
		Data: makeView(headerSize * int(numHeaderType)).ToVectorisedView(),
	})

	for _, h := range []PacketHeader{
		pk.LinkHeader(),
		pk.NetworkHeader(),
		pk.TransportHeader(),
	} {
		t.Run(h.typ.String(), func(t *testing.T) {
			h.Consume(headerSize)

			defer func() { recover() }()
			h.Push(headerSize)
			t.Fatal("Push should have panicked")
		})
	}
}

func TestPacketBufferData(t *testing.T) {
	for _, tc := range []struct {
		name    string
		makePkt func(*testing.T) *PacketBuffer
		data    string
	}{
		{
			name: "inbound packet",
			makePkt: func(*testing.T) *PacketBuffer {
				pkt := NewPacketBuffer(PacketBufferOptions{
					Data: vv("aabbbbccccccDATA"),
				})
				pkt.LinkHeader().Consume(2)
				pkt.NetworkHeader().Consume(4)
				pkt.TransportHeader().Consume(6)
				return pkt
			},
			data: "DATA",
		},
		{
			name: "outbound packet",
			makePkt: func(*testing.T) *PacketBuffer {
				pkt := NewPacketBuffer(PacketBufferOptions{
					ReserveHeaderBytes: 12,
					Data:               vv("DATA"),
				})
				copy(pkt.TransportHeader().Push(6), []byte("cccccc"))
				copy(pkt.NetworkHeader().Push(4), []byte("bbbb"))
				copy(pkt.LinkHeader().Push(2), []byte("aa"))
				return pkt
			},
			data: "DATA",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// PullUp
			for _, n := range []int{1, len(tc.data)} {
				t.Run(fmt.Sprintf("PullUp%d", n), func(t *testing.T) {
					pkt := tc.makePkt(t)
					v, ok := pkt.Data().PullUp(n)
					wantV := []byte(tc.data)[:n]
					if !ok || !bytes.Equal(v, wantV) {
						t.Errorf("pkt.Data().PullUp(%d) = %q, %t; want %q, true", n, v, ok, wantV)
					}
				})
			}
			t.Run("PullUpOutOfBounds", func(t *testing.T) {
				n := len(tc.data) + 1
				pkt := tc.makePkt(t)
				v, ok := pkt.Data().PullUp(n)
				if ok || v != nil {
					t.Errorf("pkt.Data().PullUp(%d) = %q, %t; want nil, false", n, v, ok)
				}
			})

			// DeleteFront
			for _, n := range []int{1, len(tc.data)} {
				t.Run(fmt.Sprintf("DeleteFront%d", n), func(t *testing.T) {
					pkt := tc.makePkt(t)
					pkt.Data().DeleteFront(n)

					checkData(t, pkt, []byte(tc.data)[n:])
				})
			}

			// CapLength
			for _, n := range []int{0, 1, len(tc.data)} {
				t.Run(fmt.Sprintf("CapLength%d", n), func(t *testing.T) {
					pkt := tc.makePkt(t)
					pkt.Data().CapLength(n)

					want := []byte(tc.data)
					if n < len(want) {
						want = want[:n]
					}
					checkData(t, pkt, want)
				})
			}

			// Views
			t.Run("Views", func(t *testing.T) {
				pkt := tc.makePkt(t)
				checkData(t, pkt, []byte(tc.data))
			})

			// AppendView
			t.Run("AppendView", func(t *testing.T) {
				s := "APPEND"

				pkt := tc.makePkt(t)
				pkt.Data().AppendView(buffer.View(s))

				checkData(t, pkt, []byte(tc.data+s))
			})

			// ReadFromVV
			for _, n := range []int{0, 1, 2, 7, 10, 14, 20} {
				t.Run(fmt.Sprintf("ReadFromVV%d", n), func(t *testing.T) {
					s := "TO READ"
					srcVV := vv(s, s)
					s += s

					pkt := tc.makePkt(t)
					pkt.Data().ReadFromVV(&srcVV, n)

					if n < len(s) {
						s = s[:n]
					}
					checkData(t, pkt, []byte(tc.data+s))
				})
			}

			// ExtractVV
			t.Run("ExtractVV", func(t *testing.T) {
				pkt := tc.makePkt(t)
				extractedVV := pkt.Data().ExtractVV()

				got := extractedVV.ToOwnedView()
				want := []byte(tc.data)
				if !bytes.Equal(got, want) {
					t.Errorf("pkt.Data().ExtractVV().ToOwnedView() = %q, want %q", got, want)
				}
			})
		})
	}
}

type packetContents struct {
	link      buffer.View
	network   buffer.View
	transport buffer.View
	data      buffer.View
}

func checkPacketContents(t *testing.T, prefix string, pk *PacketBuffer, want packetContents) {
	t.Helper()
	// Headers.
	checkPacketHeader(t, prefix+"pk.LinkHeader", pk.LinkHeader(), want.link)
	checkPacketHeader(t, prefix+"pk.NetworkHeader", pk.NetworkHeader(), want.network)
	checkPacketHeader(t, prefix+"pk.TransportHeader", pk.TransportHeader(), want.transport)
	// Data.
	checkData(t, pk, want.data)
	// Whole packet.
	checkViewEqual(t, prefix+"pk.Views()",
		concatViews(pk.Views()...),
		concatViews(want.link, want.network, want.transport, want.data))
	// PayloadSince.
	checkViewEqual(t, prefix+"PayloadSince(LinkHeader)",
		PayloadSince(pk.LinkHeader()),
		concatViews(want.link, want.network, want.transport, want.data))
	checkViewEqual(t, prefix+"PayloadSince(NetworkHeader)",
		PayloadSince(pk.NetworkHeader()),
		concatViews(want.network, want.transport, want.data))
	checkViewEqual(t, prefix+"PayloadSince(TransportHeader)",
		PayloadSince(pk.TransportHeader()),
		concatViews(want.transport, want.data))
}

func checkInitialPacketBuffer(t *testing.T, pk *PacketBuffer, opts PacketBufferOptions) {
	t.Helper()
	reserved := opts.ReserveHeaderBytes
	if got, want := pk.ReservedHeaderBytes(), reserved; got != want {
		t.Errorf("Initial pk.ReservedHeaderBytes() = %d, want %d", got, want)
	}
	if got, want := pk.AvailableHeaderBytes(), reserved; got != want {
		t.Errorf("Initial pk.AvailableHeaderBytes() = %d, want %d", got, want)
	}
	if got, want := pk.HeaderSize(), 0; got != want {
		t.Errorf("Initial pk.HeaderSize() = %d, want %d", got, want)
	}
	data := opts.Data.ToView()
	if got, want := pk.Size(), len(data); got != want {
		t.Errorf("Initial pk.Size() = %d, want %d", got, want)
	}
	checkPacketContents(t, "Initial ", pk, packetContents{
		data: data,
	})
}

func checkPacketHeader(t *testing.T, name string, h PacketHeader, want []byte) {
	t.Helper()
	checkViewEqual(t, name+".View()", h.View(), want)
}

func checkViewEqual(t *testing.T, what string, got, want buffer.View) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s = %x, want %x", what, got, want)
	}
}

func checkData(t *testing.T, pkt *PacketBuffer, want []byte) {
	t.Helper()
	if got := concatViews(pkt.Data().Views()...); !bytes.Equal(got, want) {
		t.Errorf("pkt.Data().Views() = 0x%x, want 0x%x", got, want)
	}
	if got := pkt.Data().Size(); got != len(want) {
		t.Errorf("pkt.Data().Size() = %d, want %d", got, len(want))
	}

	t.Run("AsRange", func(t *testing.T) {
		// Full range
		checkRange(t, pkt.Data().AsRange(), want)

		// SubRange
		for _, off := range []int{0, 1, len(want), len(want) + 1} {
			t.Run(fmt.Sprintf("SubRange%d", off), func(t *testing.T) {
				// Empty when off is greater than the size of range.
				var sub []byte
				if off < len(want) {
					sub = want[off:]
				}
				checkRange(t, pkt.Data().AsRange().SubRange(off), sub)
			})
		}

		// Capped
		for _, n := range []int{0, 1, len(want), len(want) + 1} {
			t.Run(fmt.Sprintf("Capped%d", n), func(t *testing.T) {
				sub := want
				if n < len(sub) {
					sub = sub[:n]
				}
				checkRange(t, pkt.Data().AsRange().Capped(n), sub)
			})
		}
	})
}

func checkRange(t *testing.T, r Range, data []byte) {
	if got, want := r.Size(), len(data); got != want {
		t.Errorf("r.Size() = %d, want %d", got, want)
	}
	if got := r.AsView(); !bytes.Equal(got, data) {
		t.Errorf("r.AsView() = %x, want %x", got, data)
	}
	if got := r.ToOwnedView(); !bytes.Equal(got, data) {
		t.Errorf("r.ToOwnedView() = %x, want %x", got, data)
	}
	if got, want := r.Checksum(), header.Checksum(data, 0 /* initial */); got != want {
		t.Errorf("r.Checksum() = %x, want %x", got, want)
	}
}

func vv(pieces ...string) buffer.VectorisedView {
	var views []buffer.View
	var size int
	for _, p := range pieces {
		v := buffer.View([]byte(p))
		size += len(v)
		views = append(views, v)
	}
	return buffer.NewVectorisedView(size, views)
}

func makeView(size int) buffer.View {
	b := byte(size)
	return bytes.Repeat([]byte{b}, size)
}

func concatViews(views ...buffer.View) buffer.View {
	var all buffer.View
	for _, v := range views {
		all = append(all, v...)
	}
	return all
}
