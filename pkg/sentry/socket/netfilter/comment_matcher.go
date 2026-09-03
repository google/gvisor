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

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	matcherNameComment = "comment"
	commentRevision    = 0
	// xtCommentInfoSize is sizeof(struct xt_comment_info) == [256]char.
	xtCommentInfoSize = 256
)

func init() {
	registerMatchMaker(commentMarshaler{})
}

// commentMarshaler implements matchMaker for the "comment" match. A comment is
// a pure annotation with no effect on matching; it always matches.
type commentMarshaler struct{}

func (commentMarshaler) name() string {
	return matcherNameComment
}

func (commentMarshaler) revision() uint8 {
	return commentRevision
}

func (commentMarshaler) marshal(mr matcher) []byte {
	m := mr.(*commentMatcher)
	var buf [xtCommentInfoSize]byte
	copy(buf[:], m.comment)
	return marshalEntryMatch(matcherNameComment, buf[:])
}

func (commentMarshaler) unmarshal(_ IDMapper, buf []byte, _ stack.IPHeaderFilter) (stack.Matcher, error) {
	if len(buf) < xtCommentInfoSize {
		return nil, fmt.Errorf("buf has insufficient size for comment match: %d", len(buf))
	}
	n := 0
	for n < xtCommentInfoSize && buf[n] != 0 {
		n++
	}
	return &commentMatcher{comment: string(buf[:n])}, nil
}

// commentMatcher is a no-op matcher carrying a comment string.
type commentMatcher struct {
	comment string
}

func (*commentMatcher) name() string {
	return matcherNameComment
}

func (*commentMatcher) revision() uint8 {
	return commentRevision
}

// Match implements stack.Matcher.Match: a comment always matches.
func (*commentMatcher) Match(stack.Hook, *stack.PacketBuffer, string, string) (bool, bool) {
	return true, false
}
