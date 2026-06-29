// Copyright 2026 The gVisor Authors.
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

package netfilter

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	matcherNameMark = "mark"
	markRevision    = 1
)

func init() {
	registerMatchMaker(markMarshaler{})
}

// markMarshaler implements matchMaker for mark matching.
type markMarshaler struct{}

// name implements matchMaker.name.
func (markMarshaler) name() string {
	return matcherNameMark
}

func (markMarshaler) revision() uint8 {
	return markRevision
}

// marshal implements matchMaker.marshal.
func (markMarshaler) marshal(mr matcher) []byte {
	matcher := mr.(*MarkMatcher)
	info := linux.XTMarkMtinfo1{
		Mark: matcher.mark,
		Mask: matcher.mask,
	}
	if matcher.invert {
		info.Invert = 1
	}

	buf := marshal.Marshal(&info)
	return marshalEntryMatch(matcherNameMark, buf)
}

// unmarshal implements matchMaker.unmarshal.
func (markMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < linux.SizeOfXTMarkMtinfo1 {
		return nil, fmt.Errorf("buf has insufficient size for mark match: %d", len(buf))
	}

	var info linux.XTMarkMtinfo1
	info.UnmarshalUnsafe(buf)
	nflog("parsed XTMarkMtinfo1: %+v", info)

	return &MarkMatcher{
		mark:   info.Mark,
		mask:   info.Mask,
		invert: info.Invert != 0,
	}, nil
}

// MarkMatcher matches against a packet mark.
type MarkMatcher struct {
	mark   uint32
	mask   uint32
	invert bool
}

// NewMarkMatcher creates a new MarkMatcher.
func NewMarkMatcher(mark, mask uint32, invert bool) *MarkMatcher {
	return &MarkMatcher{
		mark:   mark,
		mask:   mask,
		invert: invert,
	}
}

// name implements matcher.name.
func (*MarkMatcher) name() string {
	return matcherNameMark
}

func (*MarkMatcher) revision() uint8 {
	return markRevision
}

// Match implements Matcher.Match.
func (mm *MarkMatcher) Match(_ stack.Hook, pkt *stack.PacketBuffer, _, _ string) (bool, bool) {
	matches := (pkt.Mark & mm.mask) == mm.mark
	if matches == mm.invert {
		return false, false
	}
	return true, false
}
