// Copyright 2018 Google Inc.
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

package tcp_test

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/checker"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp/testing/context"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// createConnectedWithTimestampOption creates and connects c.ep with the
// timestamp option enabled.
func createConnectedWithTimestampOption(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptions(header.TCPSynOptions{TS: true, TSVal: 1})
}

// TestTimeStampEnabledConnect tests that netstack sends the timestamp option on
// an active connect and sets the TS Echo Reply fields correctly when the
// SYN-ACK also indicates support for the TS option and provides a TSVal.
func TestTimeStampEnabledConnect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	rep := createConnectedWithTimestampOption(c)

	// Register for read and validate that we have data to read.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	// The following tests ensure that TS option once enabled behaves
	// correctly as described in
	// https://tools.ietf.org/html/rfc7323#section-4.3.
	//
	// We are not testing delayed ACKs here, but we do test out of order
	// packet delivery and filling the sequence number hole created due to
	// the out of order packet.
	//
	// The test also verifies that the sequence numbers and timestamps are
	// as expected.
	data := []byte{1, 2, 3}

	// First we increment tsVal by a small amount.
	tsVal := rep.TSVal + 100
	rep.SendPacketWithTS(data, tsVal)
	rep.VerifyACKWithTS(tsVal)

	// Next we send an out of order packet.
	rep.NextSeqNum += 3
	tsVal += 200
	rep.SendPacketWithTS(data, tsVal)

	// The ACK should contain the original sequenceNumber and an older TS.
	rep.NextSeqNum -= 6
	rep.VerifyACKWithTS(tsVal - 200)

	// Next we fill the hole and the returned ACK should contain the
	// cumulative sequence number acking all data sent till now and have the
	// latest timestamp sent below in its TSEcr field.
	tsVal -= 100
	rep.SendPacketWithTS(data, tsVal)
	rep.NextSeqNum += 3
	rep.VerifyACKWithTS(tsVal)

	// Increment tsVal by a large value that doesn't result in a wrap around.
	tsVal += 0x7fffffff
	rep.SendPacketWithTS(data, tsVal)
	rep.VerifyACKWithTS(tsVal)

	// Increment tsVal again by a large value which should cause the
	// timestamp value to wrap around. The returned ACK should contain the
	// wrapped around timestamp in its tsEcr field and not the tsVal from
	// the previous packet sent above.
	tsVal += 0x7fffffff
	rep.SendPacketWithTS(data, tsVal)
	rep.VerifyACKWithTS(tsVal)

	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// There should be 5 views to read and each of them should
	// contain the same data.
	for i := 0; i < 5; i++ {
		got, _, err := c.EP.Read(nil)
		if err != nil {
			t.Fatalf("Unexpected error from Read: %v", err)
		}
		if want := data; bytes.Compare(got, want) != 0 {
			t.Fatalf("Data is different: got: %v, want: %v", got, want)
		}
	}
}

// TestTimeStampDisabledConnect tests that netstack sends timestamp option on an
// active connect but if the SYN-ACK doesn't specify the TS option then
// timestamp option is not enabled and future packets do not contain a
// timestamp.
func TestTimeStampDisabledConnect(t *testing.T) {
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	c.CreateConnectedWithOptions(header.TCPSynOptions{})
}

func timeStampEnabledAccept(t *testing.T, cookieEnabled bool, wndScale int, wndSize uint16) {
	savedSynCountThreshold := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = savedSynCountThreshold
	}()

	if cookieEnabled {
		tcp.SynRcvdCountThreshold = 0
	}
	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	t.Logf("Test w/ CookieEnabled = %v", cookieEnabled)
	tsVal := rand.Uint32()
	c.AcceptWithOptions(wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS, TS: true, TSVal: tsVal})

	// Now send some data and validate that timestamp is echoed correctly in the ACK.
	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received and that the timestamp option TSEcr field
	// matches the expected value.
	b := c.GetPacket()
	checker.IPv4(t, b,
		// Add 12 bytes for the timestamp option + 2 NOPs to align at 4
		// byte boundary.
		checker.PayloadLen(len(data)+header.TCPMinimumSize+12),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.Window(wndSize),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
			checker.TCPTimestampChecker(true, 0, tsVal+1),
		),
	)
}

// TestTimeStampEnabledAccept tests that if the SYN on a passive connect
// specifies the Timestamp option then the Timestamp option is sent on a SYN-ACK
// and echoes the tsVal field of the original SYN in the tcEcr field of the
// SYN-ACK. We cover the cases where SYN cookies are enabled/disabled and verify
// that Timestamp option is enabled in both cases if requested in the original
// SYN.
func TestTimeStampEnabledAccept(t *testing.T) {
	testCases := []struct {
		cookieEnabled bool
		wndScale      int
		wndSize       uint16
	}{
		{true, -1, 0xffff}, // When cookie is used window scaling is disabled.
		{false, 5, 0x8000}, // 0x8000 * 2^5 = 1<<20 = 1MB window (the default).
	}
	for _, tc := range testCases {
		timeStampEnabledAccept(t, tc.cookieEnabled, tc.wndScale, tc.wndSize)
	}
}

func timeStampDisabledAccept(t *testing.T, cookieEnabled bool, wndScale int, wndSize uint16) {
	savedSynCountThreshold := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = savedSynCountThreshold
	}()
	if cookieEnabled {
		tcp.SynRcvdCountThreshold = 0
	}

	c := context.New(t, defaultMTU)
	defer c.Cleanup()

	t.Logf("Test w/ CookieEnabled = %v", cookieEnabled)
	c.AcceptWithOptions(wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS})

	// Now send some data with the accepted connection endpoint and validate
	// that no timestamp option is sent in the TCP segment.
	data := []byte{1, 2, 3}
	view := buffer.NewView(len(data))
	copy(view, data)

	if _, err := c.EP.Write(tcpip.SlicePayload(view), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Unexpected error from Write: %v", err)
	}

	// Check that data is received and that the timestamp option is disabled
	// when SYN cookies are enabled/disabled.
	b := c.GetPacket()
	checker.IPv4(t, b,
		checker.PayloadLen(len(data)+header.TCPMinimumSize),
		checker.TCP(
			checker.DstPort(context.TestPort),
			checker.SeqNum(uint32(c.IRS)+1),
			checker.AckNum(790),
			checker.Window(wndSize),
			checker.TCPFlagsMatch(header.TCPFlagAck, ^uint8(header.TCPFlagPsh)),
			checker.TCPTimestampChecker(false, 0, 0),
		),
	)
}

// TestTimeStampDisabledAccept tests that Timestamp option is not used when the
// peer doesn't advertise it and connection is established with Accept().
func TestTimeStampDisabledAccept(t *testing.T) {
	testCases := []struct {
		cookieEnabled bool
		wndScale      int
		wndSize       uint16
	}{
		{true, -1, 0xffff}, // When cookie is used window scaling is disabled.
		{false, 5, 0x8000}, // 0x8000 * 2^5 = 1<<20 = 1MB window (the default).
	}
	for _, tc := range testCases {
		timeStampDisabledAccept(t, tc.cookieEnabled, tc.wndScale, tc.wndSize)
	}
}

func TestSendGreaterThanMTUWithOptions(t *testing.T) {
	const maxPayload = 100
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	createConnectedWithTimestampOption(c)
	testBrokenUpWrite(t, c, maxPayload)
}

func TestSegmentDropWhenTimestampMissing(t *testing.T) {
	const maxPayload = 100
	c := context.New(t, uint32(header.TCPMinimumSize+header.IPv4MinimumSize+maxPayload))
	defer c.Cleanup()

	rep := createConnectedWithTimestampOption(c)

	// Register for read.
	we, ch := waiter.NewChannelEntry(nil)
	c.WQ.EventRegister(&we, waiter.EventIn)
	defer c.WQ.EventUnregister(&we)

	droppedPacketsStat := c.Stack().Stats().DroppedPackets
	droppedPackets := droppedPacketsStat.Value()
	data := []byte{1, 2, 3}
	// Save the sequence number as we will reset it later down
	// in the test.
	savedSeqNum := rep.NextSeqNum
	rep.SendPacket(data, nil)

	select {
	case <-ch:
		t.Fatalf("Got data to read when we expect packet to be dropped")
	case <-time.After(1 * time.Second):
		// We expect that no data will be available to read.
	}

	// Assert that DroppedPackets was incremented by 1.
	if got, want := droppedPacketsStat.Value(), droppedPackets+1; got != want {
		t.Fatalf("incorrect number of dropped packets, got: %v, want: %v", got, want)
	}

	droppedPackets = droppedPacketsStat.Value()
	// Reset the sequence number so that the other endpoint accepts
	// this segment and does not treat it like an out of order delivery.
	rep.NextSeqNum = savedSeqNum
	// Now send a packet with timestamp and we should get the data.
	rep.SendPacketWithTS(data, rep.TSVal+1)

	select {
	case <-ch:
	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for data to arrive")
	}

	// Assert that DroppedPackets was not incremented by 1.
	if got, want := droppedPacketsStat.Value(), droppedPackets; got != want {
		t.Fatalf("incorrect number of dropped packets, got: %v, want: %v", got, want)
	}

	// Issue a read and we should data.
	got, _, err := c.EP.Read(nil)
	if err != nil {
		t.Fatalf("Unexpected error from Read: %v", err)
	}
	if want := data; bytes.Compare(got, want) != 0 {
		t.Fatalf("Data is different: got: %v, want: %v", got, want)
	}
}
