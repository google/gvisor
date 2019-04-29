// Copyright 2018 The gVisor Authors.
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
	"fmt"
	"reflect"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

// createConnectWithSACKPermittedOption creates and connects c.ep with the
// SACKPermitted option enabled if the stack in the context has the SACK support
// enabled.
func createConnectedWithSACKPermittedOption(c *context.Context) *context.RawEndpoint {
	return c.CreateConnectedWithOptions(header.TCPSynOptions{SACKPermitted: c.SACKEnabled()})
}

func setStackSACKPermitted(t *testing.T, c *context.Context, enable bool) {
	t.Helper()
	if err := c.Stack().SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(enable)); err != nil {
		t.Fatalf("c.s.SetTransportProtocolOption(tcp.ProtocolNumber, SACKEnabled(%v) = %v", enable, err)
	}
}

// TestSackPermittedConnect establishes a connection with the SACK option
// enabled.
func TestSackPermittedConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("stack.sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			setStackSACKPermitted(t, c, sackEnabled)
			rep := createConnectedWithSACKPermittedOption(c)
			data := []byte{1, 2, 3}

			rep.SendPacket(data, nil)
			savedSeqNum := rep.NextSeqNum
			rep.VerifyACKNoSACK()

			// Make an out of order packet and send it.
			rep.NextSeqNum += 3
			sackBlocks := []header.SACKBlock{
				{rep.NextSeqNum, rep.NextSeqNum.Add(seqnum.Size(len(data)))},
			}
			rep.SendPacket(data, nil)

			// Restore the saved sequence number so that the
			// VerifyXXX calls use the right sequence number for
			// checking ACK numbers.
			rep.NextSeqNum = savedSeqNum
			if sackEnabled {
				rep.VerifyACKHasSACK(sackBlocks)
			} else {
				rep.VerifyACKNoSACK()
			}

			// Send the missing segment.
			rep.SendPacket(data, nil)
			// The ACK should contain the cumulative ACK for all 9
			// bytes sent and no SACK blocks.
			rep.NextSeqNum += 3
			// Check that no SACK block is returned in the ACK.
			rep.VerifyACKNoSACK()
		})
	}
}

// TestSackDisabledConnect establishes a connection with the SACK option
// disabled and verifies that no SACKs are sent for out of order segments.
func TestSackDisabledConnect(t *testing.T) {
	for _, sackEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("sackEnabled: %v", sackEnabled), func(t *testing.T) {
			c := context.New(t, defaultMTU)
			defer c.Cleanup()

			setStackSACKPermitted(t, c, sackEnabled)

			rep := c.CreateConnectedWithOptions(header.TCPSynOptions{})

			data := []byte{1, 2, 3}

			rep.SendPacket(data, nil)
			savedSeqNum := rep.NextSeqNum
			rep.VerifyACKNoSACK()

			// Make an out of order packet and send it.
			rep.NextSeqNum += 3
			rep.SendPacket(data, nil)

			// The ACK should contain the older sequence number and
			// no SACK blocks.
			rep.NextSeqNum = savedSeqNum
			rep.VerifyACKNoSACK()

			// Send the missing segment.
			rep.SendPacket(data, nil)
			// The ACK should contain the cumulative ACK for all 9
			// bytes sent and no SACK blocks.
			rep.NextSeqNum += 3
			// Check that no SACK block is returned in the ACK.
			rep.VerifyACKNoSACK()
		})
	}
}

// TestSackPermittedAccept accepts and establishes a connection with the
// SACKPermitted option enabled if the connection request specifies the
// SACKPermitted option. In case of SYN cookies SACK should be disabled as we
// don't encode the SACK information in the cookie.
func TestSackPermittedAccept(t *testing.T) {
	type testCase struct {
		cookieEnabled bool
		sackPermitted bool
		wndScale      int
		wndSize       uint16
	}

	testCases := []testCase{
		// When cookie is used window scaling is disabled.
		{true, false, -1, 0xffff}, // When cookie is used window scaling is disabled.
		{false, true, 5, 0x8000},  // 0x8000 * 2^5 = 1<<20 = 1MB window (the default).
	}
	savedSynCountThreshold := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = savedSynCountThreshold
	}()
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("test: %#v", tc), func(t *testing.T) {
			if tc.cookieEnabled {
				tcp.SynRcvdCountThreshold = 0
			} else {
				tcp.SynRcvdCountThreshold = savedSynCountThreshold
			}
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("test stack.sackEnabled: %v", sackEnabled), func(t *testing.T) {
					c := context.New(t, defaultMTU)
					defer c.Cleanup()
					setStackSACKPermitted(t, c, sackEnabled)

					rep := c.AcceptWithOptions(tc.wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS, SACKPermitted: tc.sackPermitted})
					//  Now verify no SACK blocks are
					//  received when sack is disabled.
					data := []byte{1, 2, 3}
					rep.SendPacket(data, nil)
					rep.VerifyACKNoSACK()

					savedSeqNum := rep.NextSeqNum

					// Make an out of order packet and send
					// it.
					rep.NextSeqNum += 3
					sackBlocks := []header.SACKBlock{
						{rep.NextSeqNum, rep.NextSeqNum.Add(seqnum.Size(len(data)))},
					}
					rep.SendPacket(data, nil)

					// The ACK should contain the older
					// sequence number.
					rep.NextSeqNum = savedSeqNum
					if sackEnabled && tc.sackPermitted {
						rep.VerifyACKHasSACK(sackBlocks)
					} else {
						rep.VerifyACKNoSACK()
					}

					// Send the missing segment.
					rep.SendPacket(data, nil)
					// The ACK should contain the cumulative
					// ACK for all 9 bytes sent and no SACK
					// blocks.
					rep.NextSeqNum += 3
					// Check that no SACK block is returned
					// in the ACK.
					rep.VerifyACKNoSACK()
				})
			}
		})
	}
}

// TestSackDisabledAccept accepts and establishes a connection with
// the SACKPermitted option disabled and verifies that no SACKs are
// sent for out of order packets.
func TestSackDisabledAccept(t *testing.T) {
	type testCase struct {
		cookieEnabled bool
		wndScale      int
		wndSize       uint16
	}

	testCases := []testCase{
		// When cookie is used window scaling is disabled.
		{true, -1, 0xffff}, // When cookie is used window scaling is disabled.
		{false, 5, 0x8000}, // 0x8000 * 2^5 = 1<<20 = 1MB window (the default).
	}
	savedSynCountThreshold := tcp.SynRcvdCountThreshold
	defer func() {
		tcp.SynRcvdCountThreshold = savedSynCountThreshold
	}()
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("test: %#v", tc), func(t *testing.T) {
			if tc.cookieEnabled {
				tcp.SynRcvdCountThreshold = 0
			} else {
				tcp.SynRcvdCountThreshold = savedSynCountThreshold
			}
			for _, sackEnabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("test: sackEnabled: %v", sackEnabled), func(t *testing.T) {
					c := context.New(t, defaultMTU)
					defer c.Cleanup()
					setStackSACKPermitted(t, c, sackEnabled)

					rep := c.AcceptWithOptions(tc.wndScale, header.TCPSynOptions{MSS: defaultIPv4MSS})

					//  Now verify no SACK blocks are
					//  received when sack is disabled.
					data := []byte{1, 2, 3}
					rep.SendPacket(data, nil)
					rep.VerifyACKNoSACK()
					savedSeqNum := rep.NextSeqNum

					// Make an out of order packet and send
					// it.
					rep.NextSeqNum += 3
					rep.SendPacket(data, nil)

					// The ACK should contain the older
					// sequence number and no SACK blocks.
					rep.NextSeqNum = savedSeqNum
					rep.VerifyACKNoSACK()

					// Send the missing segment.
					rep.SendPacket(data, nil)
					// The ACK should contain the cumulative
					// ACK for all 9 bytes sent and no SACK
					// blocks.
					rep.NextSeqNum += 3
					// Check that no SACK block is returned
					// in the ACK.
					rep.VerifyACKNoSACK()
				})
			}
		})
	}
}

func TestUpdateSACKBlocks(t *testing.T) {
	testCases := []struct {
		segStart   seqnum.Value
		segEnd     seqnum.Value
		rcvNxt     seqnum.Value
		sackBlocks []header.SACKBlock
		updated    []header.SACKBlock
	}{
		// Trivial cases where current SACK block list is empty and we
		// have an out of order delivery.
		{10, 11, 2, []header.SACKBlock{}, []header.SACKBlock{{10, 11}}},
		{10, 12, 2, []header.SACKBlock{}, []header.SACKBlock{{10, 12}}},
		{10, 20, 2, []header.SACKBlock{}, []header.SACKBlock{{10, 20}}},

		// Cases where current SACK block list is not empty and we have
		// an out of order delivery. Tests that the updated SACK block
		// list has the first block as the one that contains the new
		// SACK block representing the segment that was just delivered.
		{10, 11, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 11}, {12, 20}}},
		{24, 30, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{24, 30}, {12, 20}}},
		{24, 30, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{24, 30}, {12, 20}, {32, 40}}},

		// Ensure that we only retain header.MaxSACKBlocks and drop the
		// oldest one if adding a new block exceeds
		// header.MaxSACKBlocks.
		{24, 30, 9,
			[]header.SACKBlock{{12, 20}, {32, 40}, {42, 50}, {52, 60}, {62, 70}, {72, 80}},
			[]header.SACKBlock{{24, 30}, {12, 20}, {32, 40}, {42, 50}, {52, 60}, {62, 70}}},

		// Cases where segment extends an existing SACK block.
		{10, 12, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 20}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 22}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{10, 22}}},
		{15, 22, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{12, 22}}},
		{15, 25, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{12, 25}}},
		{11, 25, 9, []header.SACKBlock{{12, 20}}, []header.SACKBlock{{11, 25}}},
		{10, 12, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{10, 20}, {32, 40}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{10, 22}, {32, 40}}},
		{10, 22, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{10, 22}, {32, 40}}},
		{15, 22, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{12, 22}, {32, 40}}},
		{15, 25, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{12, 25}, {32, 40}}},
		{11, 25, 9, []header.SACKBlock{{12, 20}, {32, 40}}, []header.SACKBlock{{11, 25}, {32, 40}}},

		// Cases where segment contains rcvNxt.
		{10, 20, 15, []header.SACKBlock{{20, 30}, {40, 50}}, []header.SACKBlock{{40, 50}}},
	}

	for _, tc := range testCases {
		var sack tcp.SACKInfo
		copy(sack.Blocks[:], tc.sackBlocks)
		sack.NumBlocks = len(tc.sackBlocks)
		tcp.UpdateSACKBlocks(&sack, tc.segStart, tc.segEnd, tc.rcvNxt)
		if got, want := sack.Blocks[:sack.NumBlocks], tc.updated; !reflect.DeepEqual(got, want) {
			t.Errorf("UpdateSACKBlocks(%v, %v, %v, %v), got: %v, want: %v", tc.sackBlocks, tc.segStart, tc.segEnd, tc.rcvNxt, got, want)
		}

	}
}

func TestTrimSackBlockList(t *testing.T) {
	testCases := []struct {
		rcvNxt     seqnum.Value
		sackBlocks []header.SACKBlock
		trimmed    []header.SACKBlock
	}{
		// Simple cases where we trim whole entries.
		{2, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}},
		{21, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{22, 30}, {32, 40}}},
		{31, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{32, 40}}},
		{40, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{}},
		// Cases where we need to update a block.
		{12, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{12, 20}, {22, 30}, {32, 40}}},
		{23, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{23, 30}, {32, 40}}},
		{33, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{{33, 40}}},
		{41, []header.SACKBlock{{10, 20}, {22, 30}, {32, 40}}, []header.SACKBlock{}},
	}
	for _, tc := range testCases {
		var sack tcp.SACKInfo
		copy(sack.Blocks[:], tc.sackBlocks)
		sack.NumBlocks = len(tc.sackBlocks)
		tcp.TrimSACKBlockList(&sack, tc.rcvNxt)
		if got, want := sack.Blocks[:sack.NumBlocks], tc.trimmed; !reflect.DeepEqual(got, want) {
			t.Errorf("TrimSackBlockList(%v, %v), got: %v, want: %v", tc.sackBlocks, tc.rcvNxt, got, want)
		}
	}
}
