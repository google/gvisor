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

package header_test

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

// TestIGMPHeader tests the functions within header.igmp
func TestIGMPHeader(t *testing.T) {
	const maxRespTimeTenthSec = 0xF0
	b := []byte{
		0x11,                // IGMP Type, Membership Query
		maxRespTimeTenthSec, // Maximum Response Time
		0xC0, 0xC0,          // Checksum
		0x01, 0x02, 0x03, 0x04, // Group Address
	}

	igmpHeader := header.IGMP(b)

	if got, want := igmpHeader.Type(), header.IGMPMembershipQuery; got != want {
		t.Errorf("got igmpHeader.Type() = %x, want = %x", got, want)
	}

	if got, want := igmpHeader.MaxRespTime(), header.DecisecondToDuration(maxRespTimeTenthSec); got != want {
		t.Errorf("got igmpHeader.MaxRespTime() = %s, want = %s", got, want)
	}

	if got, want := igmpHeader.Checksum(), uint16(0xC0C0); got != want {
		t.Errorf("got igmpHeader.Checksum() = %x, want = %x", got, want)
	}

	if got, want := igmpHeader.GroupAddress(), testutil.MustParse4("1.2.3.4"); got != want {
		t.Errorf("got igmpHeader.GroupAddress() = %s, want = %s", got, want)
	}

	igmpType := header.IGMPv2MembershipReport
	igmpHeader.SetType(igmpType)
	if got := igmpHeader.Type(); got != igmpType {
		t.Errorf("got igmpHeader.Type() = %x, want = %x", got, igmpType)
	}
	if got := header.IGMPType(b[0]); got != igmpType {
		t.Errorf("got IGMPtype in backing buffer = %x, want %x", got, igmpType)
	}

	respTime := byte(0x02)
	igmpHeader.SetMaxRespTime(respTime)
	if got, want := igmpHeader.MaxRespTime(), header.DecisecondToDuration(uint16(respTime)); got != want {
		t.Errorf("got igmpHeader.MaxRespTime() = %s, want = %s", got, want)
	}

	checksum := uint16(0x0102)
	igmpHeader.SetChecksum(checksum)
	if got := igmpHeader.Checksum(); got != checksum {
		t.Errorf("got igmpHeader.Checksum() = %x, want = %x", got, checksum)
	}

	groupAddress := testutil.MustParse4("4.3.2.1")
	igmpHeader.SetGroupAddress(groupAddress)
	if got := igmpHeader.GroupAddress(); got != groupAddress {
		t.Errorf("got igmpHeader.GroupAddress() = %s, want = %s", got, groupAddress)
	}
}

// TestIGMPChecksum ensures that the checksum calculator produces the expected
// checksum.
func TestIGMPChecksum(t *testing.T) {
	b := []byte{
		0x11,       // IGMP Type, Membership Query
		0xF0,       // Maximum Response Time
		0xC0, 0xC0, // Checksum
		0x01, 0x02, 0x03, 0x04, // Group Address
	}

	igmpHeader := header.IGMP(b)

	// Calculate the initial checksum after setting the checksum temporarily to 0
	// to avoid checksumming the checksum.
	initialChecksum := igmpHeader.Checksum()
	igmpHeader.SetChecksum(0)
	xsum := ^checksum.Checksum(b, 0)
	igmpHeader.SetChecksum(initialChecksum)

	if got := header.IGMPCalculateChecksum(igmpHeader); got != xsum {
		t.Errorf("got IGMPCalculateChecksum = %x, want %x", got, xsum)
	}
}

func TestDecisecondToDuration(t *testing.T) {
	const valueInDeciseconds = 5
	if got, want := header.DecisecondToDuration(valueInDeciseconds), valueInDeciseconds*time.Second/10; got != want {
		t.Fatalf("got header.DecisecondToDuration(%d) = %s, want = %s", valueInDeciseconds, got, want)
	}
}

func TestIGMPv3Query(t *testing.T) {
	const (
		exponentialQueryIntervalStartCode = 128
		mantQQICBits                      = 4
	)

	qrvs := []uint8{0, 1, 2, 3, 4, 5, 6, 7}

	type qqicTest struct {
		val              uint8
		expectedInterval time.Duration
	}

	exponentialQQIC := func(mant, exp uint8) qqicTest {
		return qqicTest{
			val:              exponentialQueryIntervalStartCode | mant | exp<<mantQQICBits,
			expectedInterval: ((time.Duration(mant) | 0x10) << (time.Duration(exp) + 3)) * time.Second,
		}
	}

	queryIntervalCodes := []qqicTest{
		{
			val:              0,
			expectedInterval: 0,
		},
		{
			val:              1,
			expectedInterval: time.Second,
		},
		{
			val:              exponentialQueryIntervalStartCode - 1,
			expectedInterval: (exponentialQueryIntervalStartCode - 1) * time.Second,
		},
		{
			val:              exponentialQueryIntervalStartCode,
			expectedInterval: exponentialQueryIntervalStartCode * time.Second,
		},
		exponentialQQIC(0, 0),
		exponentialQQIC(1, 0),
		exponentialQQIC(0, 1),
		exponentialQQIC(1, 1),
	}

	sourceAddrs := []tcpip.Address{
		testutil.MustParse4("1.0.0.1"),
		testutil.MustParse4("2.0.0.2"),
		testutil.MustParse4("3.0.0.3"),
	}

	sources := []struct {
		count      uint16
		expectedOK bool
	}{
		{
			count:      0,
			expectedOK: true,
		},
		{
			count:      0,
			expectedOK: true,
		},
		{
			count:      1,
			expectedOK: true,
		},
		{
			count:      uint16(len(sourceAddrs)),
			expectedOK: true,
		},
		{
			count:      uint16(len(sourceAddrs) + 1),
			expectedOK: false,
		},
	}

	for _, respCode := range []uint8{0x01, 0x10} {
		for _, qrv := range qrvs {
			for _, qqic := range queryIntervalCodes {
				for _, source := range sources {
					t.Run(fmt.Sprintf("MaxRespCode=%d QRV=%d QQIC=%d Sources=%d", respCode, qrv, qqic.val, source.count), func(t *testing.T) {
						b := []byte{
							// Type,
							0x11,

							// Maximum Response Code
							0,

							// Checksum
							0, 0,

							// GroupAddress
							1, 2, 3, 4,

							// Resv, S, QRV
							qrv,

							// QQIC
							qqic.val,

							// Number of Sources
							0, 0,

							// Sources
							1, 0, 0, 1,
							2, 0, 0, 2,
							3, 0, 0, 3,
						}

						b[1] = respCode
						binary.BigEndian.PutUint16(b[10:], source.count)

						query := header.IGMPv3Query(b)
						if got := query.MaximumResponseCode(); got != respCode {
							t.Errorf("got query.MaximumResponseCode() = %d, want = %d", got, respCode)
						}
						if got := query.QuerierRobustnessVariable(); got != qrv {
							t.Errorf("got query.QuerierRobustnessVariable() = %d, want = %d", got, qrv)
						}
						if got := query.QuerierQueryInterval(); got != qqic.expectedInterval {
							t.Errorf("got query.QuerierQueryInterval() = %s, want = %s", got, qqic.expectedInterval)
						}
						if got, want := query.GroupAddress(), tcpip.AddrFrom4([4]byte{1, 2, 3, 4}); got != want {
							t.Errorf("got query.GroupAddress() = %s, want = %s", got, want)
						}

						iterator, ok := query.Sources()
						if ok != source.expectedOK {
							t.Errorf("got query.Sources() = (_, %t), want = (_, %t)", ok, source.expectedOK)
						}
						if !source.expectedOK {
							return
						}

						sourceAddrs := sourceAddrs[:source.count]
						for i := uint16(0); ; i++ {
							if len(sourceAddrs) == 0 {
								break
							}

							source, ok := iterator.Next()
							if !ok {
								t.Fatalf("expected %d-th source", i)
							}
							if source != sourceAddrs[0] {
								t.Errorf("got %d-th source = %s, want = %s", i, source, sourceAddrs[0])
							}

							sourceAddrs = sourceAddrs[1:]
						}
						if len(sourceAddrs) != 0 {
							t.Errorf("missing sources = %#v", sourceAddrs)
						}
						if source, ok := iterator.Next(); ok {
							t.Errorf("unexpected source = %s", source)
						}
					})
				}
			}
		}
	}
}

func TestIGMPv3Report(t *testing.T) {
	var (
		mcastAddr1 = testutil.MustParse4("224.1.0.1")
		mcastAddr2 = testutil.MustParse4("224.2.0.2")
		mcastAddr3 = testutil.MustParse4("224.3.0.3")

		srcAddr1 = testutil.MustParse4("1.0.0.1")
		srcAddr2 = testutil.MustParse4("2.0.0.2")
		srcAddr3 = testutil.MustParse4("3.0.0.3")
	)

	tests := []struct {
		name       string
		serializer header.IGMPv3ReportSerializer
	}{
		{
			name:       "zero reports",
			serializer: header.IGMPv3ReportSerializer{},
		},
		{
			name: "one record with one source",
			serializer: header.IGMPv3ReportSerializer{
				Records: []header.IGMPv3ReportGroupAddressRecordSerializer{
					{
						RecordType:   header.IGMPv3ReportRecordModeIsInclude,
						GroupAddress: mcastAddr1,
						Sources:      []tcpip.Address{srcAddr1},
					},
				},
			},
		},
		{
			name: "multiple records with multiple sources",
			serializer: header.IGMPv3ReportSerializer{
				Records: []header.IGMPv3ReportGroupAddressRecordSerializer{
					{
						RecordType:   header.IGMPv3ReportRecordModeIsInclude,
						GroupAddress: mcastAddr1,
						Sources:      nil,
					},
					{
						RecordType:   header.IGMPv3ReportRecordModeIsExclude,
						GroupAddress: mcastAddr2,
						Sources:      []tcpip.Address{srcAddr1, srcAddr2, srcAddr3},
					},
					{
						RecordType:   header.IGMPv3ReportRecordChangeToIncludeMode,
						GroupAddress: mcastAddr3,
						Sources:      []tcpip.Address{srcAddr1, srcAddr2},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := make([]byte, test.serializer.Length())
			test.serializer.SerializeInto(b)

			report := header.IGMPv3Report(b)

			if got, want := report.Checksum(), header.IGMPCalculateChecksum(header.IGMP(report)); got != want {
				t.Errorf("got report.Checksum() = %d, want = %d", got, want)
			}

			expectedRecords := test.serializer.Records

			records := report.GroupAddressRecords()
			for {
				if len(expectedRecords) == 0 {
					break
				}

				record, res := records.Next()
				if res != header.IGMPv3ReportGroupAddressRecordIteratorNextOk {
					t.Fatalf("got records.Next() = (%#v, %d), want = (_, %d)", record, res, header.IGMPv3ReportGroupAddressRecordIteratorNextOk)
				}

				if got, want := record.RecordType(), expectedRecords[0].RecordType; got != want {
					t.Errorf("got record.RecordType() = %d, want = %d", got, want)
				}

				if got := record.AuxDataLen(); got != 0 {
					t.Errorf("got record.AuxDataLen() = %d, want = 0", got)
				}

				if got, want := record.GroupAddress(), expectedRecords[0].GroupAddress; got != want {
					t.Errorf("got record.GroupAddress() = %s, want = %s", got, want)
				}

				sources, ok := record.Sources()
				if !ok {
					t.Error("got record.Sources() = (_, false), want = (_, true)")
					continue
				}

				expectedSources := expectedRecords[0].Sources
				for {
					if len(expectedSources) == 0 {
						break
					}

					source, ok := sources.Next()
					if !ok {
						t.Fatal("got sources.Next() = (_, false), want = (_, true)")
					}
					if source != expectedSources[0] {
						t.Errorf("got sources.Next() = %s, want = %s", source, expectedSources[0])
					}

					expectedSources = expectedSources[1:]
				}

				expectedRecords = expectedRecords[1:]
			}

			if record, res := records.Next(); res != header.IGMPv3ReportGroupAddressRecordIteratorNextDone {
				t.Fatalf("got records.Next() = (%#v, %d), want = (_, %d)", record, res, header.IGMPv3ReportGroupAddressRecordIteratorNextDone)
			}
		})
	}
}
