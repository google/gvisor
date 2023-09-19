// Copyright 2021 The gVisor Authors.
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

// Package testutil provides helper functions for netstack unit tests.
package testutil

import (
	"fmt"
	"net"
	"reflect"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// MustParse4 parses an IPv4 string (e.g. "192.168.1.1") into a tcpip.Address.
// Passing an IPv4-mapped IPv6 address will yield only the 4 IPv4 bytes.
func MustParse4(addr string) tcpip.Address {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		panic(fmt.Sprintf("Parse4 expects IPv4 addresses, but was passed %q", addr))
	}
	return tcpip.AddrFrom4Slice(ip)
}

// MustParse6 parses an IPv6 string (e.g. "fe80::1") into a tcpip.Address. Passing
// an IPv4 address will yield an IPv4-mapped IPv6 address.
func MustParse6(addr string) tcpip.Address {
	ip := net.ParseIP(addr).To16()
	if ip == nil {
		panic(fmt.Sprintf("Parse6 was passed malformed address %q", addr))
	}
	return tcpip.AddrFrom16Slice(ip)
}

func checkFieldCounts(ref, multi reflect.Value) error {
	refTypeName := ref.Type().Name()
	multiTypeName := multi.Type().Name()
	refNumField := ref.NumField()
	multiNumField := multi.NumField()

	if refNumField != multiNumField {
		return fmt.Errorf("type %s has an incorrect number of fields: got = %d, want = %d (same as type %s)", multiTypeName, multiNumField, refNumField, refTypeName)
	}

	return nil
}

func validateField(ref reflect.Value, refName string, m tcpip.MultiCounterStat, multiName string) error {
	s, ok := ref.Addr().Interface().(**tcpip.StatCounter)
	if !ok {
		return fmt.Errorf("expected ref type's to be *StatCounter, but its type is %s", ref.Type().Elem().Name())
	}

	// The field names are expected to match (case insensitive).
	if !strings.EqualFold(refName, multiName) {
		return fmt.Errorf("wrong field name: got = %s, want = %s", multiName, refName)
	}

	base := (*s).Value()
	m.Increment()
	if (*s).Value() != base+1 {
		return fmt.Errorf("updates to the '%s MultiCounterStat' counters are not reflected in the '%s CounterStat'", multiName, refName)
	}

	return nil
}

func validateIntegralMapField(ref reflect.Value, refName string, m tcpip.MultiIntegralStatCounterMap, multiName string) error {
	// The field names are expected to match (case insensitive).
	if !strings.EqualFold(refName, multiName) {
		return fmt.Errorf("wrong field name: got = %s, want = %s", multiName, refName)
	}
	s, ok := ref.Addr().Interface().(**tcpip.IntegralStatCounterMap)
	if !ok {
		return fmt.Errorf("field is not an IntegralStatCounterMap")
	}

	const key = 42

	getValue := func() uint64 {
		counter, ok := (*s).Get(key)
		if !ok {
			return 0
		}
		return counter.Value()
	}

	before := getValue()

	m.Increment(key)

	after := getValue()

	if after != before+1 {
		return fmt.Errorf("updates to the '%s MultiCounterStat' counters are not reflected in the '%s CounterStat'", multiName, refName)
	}

	return nil
}

func validateMultiCounterStats(multi reflect.Value, counters []reflect.Value) (foundMultiCounterStat, foundMultiIntegralStatCounterMap bool, err error) {
	for _, c := range counters {
		if err := checkFieldCounts(c, multi); err != nil {
			return false, false, err
		}
	}

	for i := 0; i < multi.NumField(); i++ {
		multiName := multi.Type().Field(i).Name
		multiUnsafe := unsafeExposeUnexportedFields(multi.Field(i))

		switch m := multiUnsafe.Addr().Interface().(type) {
		case *tcpip.MultiCounterStat:
			foundMultiCounterStat = true
			for _, c := range counters {
				if err := validateField(unsafeExposeUnexportedFields(c.Field(i)), c.Type().Field(i).Name, *m, multiName); err != nil {
					return false, false, err
				}
			}
		case *tcpip.MultiIntegralStatCounterMap:
			foundMultiIntegralStatCounterMap = true
			for _, c := range counters {
				if err := validateIntegralMapField(unsafeExposeUnexportedFields(c.Field(i)), c.Type().Field(i).Name, *m, multiName); err != nil {
					return false, false, err
				}
			}
		default:
			var countersNextField []reflect.Value
			for _, c := range counters {
				countersNextField = append(countersNextField, c.Field(i))
			}
			innerFoundMultiCounterStat, innerFoundMultiIntegralStatCounterMap, err := validateMultiCounterStats(multi.Field(i), countersNextField)
			if err != nil {
				return false, false, err
			}
			foundMultiCounterStat = foundMultiCounterStat || innerFoundMultiCounterStat
			foundMultiIntegralStatCounterMap = foundMultiIntegralStatCounterMap || innerFoundMultiIntegralStatCounterMap
		}
	}

	return foundMultiCounterStat, foundMultiIntegralStatCounterMap, nil
}

// ValidateMultiCounterStatsOptions holds options used when validating multi
// counter stat structs.
type ValidateMultiCounterStatsOptions struct {
	ExpectMultiCounterStat            bool
	ExpectMultiIntegralStatCounterMap bool
}

// ValidateMultiCounterStats verifies that every counter stored in multi is
// correctly tracking its counterpart in the given counters.
func ValidateMultiCounterStats(multi reflect.Value, counters []reflect.Value, options ValidateMultiCounterStatsOptions) error {
	foundMultiCounterStat, foundMultiIntegralStatCounterMap, err := validateMultiCounterStats(multi, counters)
	if err != nil {
		return err
	}
	if foundMultiCounterStat != options.ExpectMultiCounterStat {
		return fmt.Errorf("got %T presence: %t, want: %t", (*tcpip.MultiCounterStat)(nil), foundMultiCounterStat, options.ExpectMultiCounterStat)
	}
	if foundMultiIntegralStatCounterMap != options.ExpectMultiIntegralStatCounterMap {
		return fmt.Errorf("got %T presence: %t, want: %t", (*tcpip.MultiIntegralStatCounterMap)(nil), foundMultiIntegralStatCounterMap, options.ExpectMultiIntegralStatCounterMap)
	}

	return nil
}

// MustParseLink parses a Link string into a tcpip.LinkAddress, panicking on
// error.
//
// The string must be in the format aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff.
func MustParseLink(addr string) tcpip.LinkAddress {
	parsed, err := tcpip.ParseMACAddress(addr)
	if err != nil {
		panic(fmt.Sprintf("tcpip.ParseMACAddress(%s): %s", addr, err))
	}
	return parsed
}
