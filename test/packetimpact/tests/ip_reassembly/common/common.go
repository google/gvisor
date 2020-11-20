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

// Package common contains test cases for IP reassembly.
package common

// FragmentInfo describes the meta data of an IP fragment.
type FragmentInfo struct {
	// Offset of the fragment.
	Offset uint16

	// Size of the fragment.
	Size uint16

	// More specifies whether there are more fragments after this one or not.
	More bool

	// ID of the fragment.
	ID uint16
}

// TestCase is a IP reassembly test case.
type TestCase struct {
	// Description of the test case.
	Description string

	// IPPayloadLen is the length of the payload.
	IPPayloadLen int

	// Fragments holds the meta data of every fragment we will transmit.
	Fragments []FragmentInfo

	// ExpectReply specifies whether the DUT is expected to reply or not.
	ExpectReply bool
}

// Basic test case.
var Basic = TestCase{
	Description:  "basic reassembly",
	IPPayloadLen: 3000,
	Fragments: []FragmentInfo{
		{Offset: 0, Size: 1000, ID: 5, More: true},
		{Offset: 1000, Size: 1000, ID: 5, More: true},
		{Offset: 2000, Size: 1000, ID: 5, More: false},
	},
	ExpectReply: true,
}

// OutOfOrder test case.
var OutOfOrder = TestCase{
	Description:  "out of order fragments",
	IPPayloadLen: 3000,
	Fragments: []FragmentInfo{
		{Offset: 2000, Size: 1000, ID: 6, More: false},
		{Offset: 0, Size: 1000, ID: 6, More: true},
		{Offset: 1000, Size: 1000, ID: 6, More: true},
	},
	ExpectReply: true,
}

// Duplicate test case.
var Duplicate = TestCase{
	Description:  "duplicated fragments",
	IPPayloadLen: 3000,
	Fragments: []FragmentInfo{
		{Offset: 0, Size: 1000, ID: 7, More: true},
		{Offset: 1000, Size: 1000, ID: 7, More: true},
		{Offset: 1000, Size: 1000, ID: 7, More: true},
		{Offset: 2000, Size: 1000, ID: 7, More: false},
	},
	ExpectReply: true,
}

// Subset test case.
var Subset = TestCase{
	Description:  "fragment subset",
	IPPayloadLen: 3000,
	Fragments: []FragmentInfo{
		{Offset: 0, Size: 1000, ID: 8, More: true},
		{Offset: 1000, Size: 1000, ID: 8, More: true},
		{Offset: 512, Size: 256, ID: 8, More: true},
		{Offset: 2000, Size: 1000, ID: 8, More: false},
	},
	ExpectReply: true,
}

// Overlap test case.
var Overlap = TestCase{
	Description:  "fragment overlap",
	IPPayloadLen: 3000,
	Fragments: []FragmentInfo{
		{Offset: 0, Size: 1000, ID: 9, More: true},
		{Offset: 1512, Size: 1000, ID: 9, More: true},
		{Offset: 1000, Size: 1000, ID: 9, More: true},
		{Offset: 2000, Size: 1000, ID: 9, More: false},
	},
	ExpectReply: false,
}
