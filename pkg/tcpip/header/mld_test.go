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

package header

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

func TestMLD(t *testing.T) {
	b := []byte{
		// Maximum Response Delay
		0, 0,

		// Reserved
		0, 0,

		// MulticastAddress
		1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,
	}

	const maxRespDelay = 513
	binary.BigEndian.PutUint16(b, maxRespDelay)

	mld := MLD(b)

	if got, want := mld.MaximumResponseDelay(), maxRespDelay*time.Millisecond; got != want {
		t.Errorf("got mld.MaximumResponseDelay() = %s, want = %s", got, want)
	}

	const newMaxRespDelay = 1234
	mld.SetMaximumResponseDelay(newMaxRespDelay)
	if got, want := mld.MaximumResponseDelay(), newMaxRespDelay*time.Millisecond; got != want {
		t.Errorf("got mld.MaximumResponseDelay() = %s, want = %s", got, want)
	}

	if got, want := mld.MulticastAddress(), tcpip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}); got != want {
		t.Errorf("got mld.MulticastAddress() = %s, want = %s", got, want)
	}

	multicastAddress := tcpip.AddrFrom16([16]byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0})
	mld.SetMulticastAddress(multicastAddress)
	if got := mld.MulticastAddress(); got != multicastAddress {
		t.Errorf("got mld.MulticastAddress() = %s, want = %s", got, multicastAddress)
	}
}

func TestMLDv2MaximumResponseDelay(t *testing.T) {
	const (
		exponentialResponseDelayStartCode = 32768
		mantMaxRespBits                   = 12
	)

	type respCodeTest struct {
		maxResponseCode          uint16
		expectedMaxResponseDelay time.Duration
	}

	exponentialRespDelay := func(mant, exp uint16) respCodeTest {
		return respCodeTest{
			maxResponseCode:          exponentialResponseDelayStartCode | mant | exp<<mantMaxRespBits,
			expectedMaxResponseDelay: ((time.Duration(mant) | 0x1000) << (time.Duration(exp) + 3)) * time.Millisecond,
		}
	}

	tests := []respCodeTest{
		{
			maxResponseCode:          0,
			expectedMaxResponseDelay: 0,
		},
		{
			maxResponseCode:          1,
			expectedMaxResponseDelay: time.Millisecond,
		},
		{
			maxResponseCode:          exponentialResponseDelayStartCode - 1,
			expectedMaxResponseDelay: (exponentialResponseDelayStartCode - 1) * time.Millisecond,
		},
		exponentialRespDelay(0, 0),
		exponentialRespDelay(1, 0),
		exponentialRespDelay(0, 1),
		exponentialRespDelay(1, 1),
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("Code=%d", test.maxResponseCode), func(t *testing.T) {
			if got := MLDv2MaximumResponseDelay(test.maxResponseCode); got != test.expectedMaxResponseDelay {
				t.Errorf("got MLDv2MaximumResponseDelay(%d) = %s, want = %s", test.maxResponseCode, got, test.expectedMaxResponseDelay)
			}
		})
	}
}

func TestMLDv2Query(t *testing.T) {
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
		testutil.MustParse6("a00::a"),
		testutil.MustParse6("b00::b"),
		testutil.MustParse6("c00::c"),
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

	for _, respCode := range []uint16{0x0001, 0x0100} {
		for _, qrv := range qrvs {
			for _, qqic := range queryIntervalCodes {
				for _, source := range sources {
					t.Run(fmt.Sprintf("MaxRespCode=%d QRV=%d QQIC=%d Sources=%d", respCode, qrv, qqic.val, source.count), func(t *testing.T) {
						b := []byte{
							// Maximum Response Code
							0, 0,

							// Reserved
							0, 0,

							// MulticastAddress
							1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6,

							// Resv, S, QRV
							qrv,

							// QQIC
							qqic.val,

							// Number of Sources
							0, 0,

							// Sources
							0xA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xA,
							0xB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xB,
							0xC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xC,
						}

						binary.BigEndian.PutUint16(b[mldMaximumResponseDelayOffset:], respCode)
						binary.BigEndian.PutUint16(b[mldv2QueryNumberOfSourcesOffset:], source.count)

						query := MLDv2Query(b)
						if got := query.MaximumResponseCode(); got != respCode {
							t.Errorf("got query.MaximumResponseCode() = %d, want = %d", got, respCode)
						}
						if got := query.QuerierRobustnessVariable(); got != qrv {
							t.Errorf("got query.QuerierRobustnessVariable() = %d, want = %d", got, qrv)
						}
						if got := query.QuerierQueryInterval(); got != qqic.expectedInterval {
							t.Errorf("got query.QuerierQueryInterval() = %s, want = %s", got, qqic.expectedInterval)
						}
						if got, want := query.MulticastAddress(), tcpip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6}); got != want {
							t.Errorf("got query.MulticastAddress() = %s, want = %s", got, want)
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

func TestMLDv2Report(t *testing.T) {
	var (
		mcastAddr1 = testutil.MustParse6("ff02::a")
		mcastAddr2 = testutil.MustParse6("ff02::b")
		mcastAddr3 = testutil.MustParse6("ff02::c")

		srcAddr1 = testutil.MustParse6("a::a")
		srcAddr2 = testutil.MustParse6("b::b")
		srcAddr3 = testutil.MustParse6("c::c")
	)

	tests := []struct {
		name       string
		serializer MLDv2ReportSerializer
	}{
		{
			name:       "zero reports",
			serializer: MLDv2ReportSerializer{},
		},
		{
			name: "one record with one source",
			serializer: MLDv2ReportSerializer{
				Records: []MLDv2ReportMulticastAddressRecordSerializer{
					{
						RecordType:       MLDv2ReportRecordModeIsInclude,
						MulticastAddress: mcastAddr1,
						Sources:          []tcpip.Address{srcAddr1},
					},
				},
			},
		},
		{
			name: "multiple records with multiple sources",
			serializer: MLDv2ReportSerializer{
				Records: []MLDv2ReportMulticastAddressRecordSerializer{
					{
						RecordType:       MLDv2ReportRecordModeIsInclude,
						MulticastAddress: mcastAddr1,
						Sources:          nil,
					},
					{
						RecordType:       MLDv2ReportRecordModeIsExclude,
						MulticastAddress: mcastAddr2,
						Sources:          []tcpip.Address{srcAddr1, srcAddr2, srcAddr3},
					},
					{
						RecordType:       MLDv2ReportRecordChangeToIncludeMode,
						MulticastAddress: mcastAddr3,
						Sources:          []tcpip.Address{srcAddr1, srcAddr2},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := make([]byte, test.serializer.Length())
			test.serializer.SerializeInto(b)

			report := MLDv2Report(b)
			expectedRecords := test.serializer.Records

			records := report.MulticastAddressRecords()
			for {
				if len(expectedRecords) == 0 {
					break
				}

				record, res := records.Next()
				if res != MLDv2ReportMulticastAddressRecordIteratorNextOk {
					t.Fatalf("got records.Next() = (%#v, %d), want = (_, %d)", record, res, MLDv2ReportMulticastAddressRecordIteratorNextOk)
				}

				if got, want := record.RecordType(), expectedRecords[0].RecordType; got != want {
					t.Errorf("got record.RecordType() = %d, want = %d", got, want)
				}

				if got := record.AuxDataLen(); got != 0 {
					t.Errorf("got record.AuxDataLen() = %d, want = 0", got)
				}

				if got, want := record.MulticastAddress(), expectedRecords[0].MulticastAddress; got != want {
					t.Errorf("got record.MulticastAddress() = %s, want = %s", got, want)
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

			if record, res := records.Next(); res != MLDv2ReportMulticastAddressRecordIteratorNextDone {
				t.Fatalf("got records.Next() = (%#v, %d), want = (_, %d)", record, res, MLDv2ReportMulticastAddressRecordIteratorNextDone)
			}
		})
	}
}
