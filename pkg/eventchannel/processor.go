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

package eventchannel

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/pkg/eventchannel/eventchannel_go_proto"
)

// eventProcessor carries display state across multiple events.
type eventProcessor struct {
	filtering bool
	// filtered is the number of events omitted since printing the last matching
	// event. Only meaningful when filtering == true.
	filtered uint64
	// allowlist is the set of event names to display. If empty, all events are
	// displayed.
	allowlist map[string]bool
}

// newEventProcessor creates a new EventProcessor with filters.
func newEventProcessor(filters []string) *eventProcessor {
	e := &eventProcessor{
		filtering: len(filters) > 0,
		allowlist: make(map[string]bool),
	}
	for _, f := range filters {
		e.allowlist[f] = true
	}
	return e
}

// processOne reads, parses and displays a single event from the event channel.
//
// The event channel is a stream of (msglen, payload) packets; this function
// processes a single such packet. The msglen is a uvarint-encoded length for
// the associated payload. The payload is a binary-encoded 'Any' protobuf, which
// in turn encodes an arbitrary event protobuf.
func (e *eventProcessor) processOne(src io.Reader, out *os.File) error {
	// Read and parse the msglen.
	lenbuf := make([]byte, binary.MaxVarintLen64)
	if _, err := io.ReadFull(src, lenbuf); err != nil {
		return err
	}
	msglen, consumed := binary.Uvarint(lenbuf)
	if consumed <= 0 {
		return fmt.Errorf("couldn't parse the message length")
	}

	// Read the payload.
	buf := make([]byte, msglen)
	// Copy any unused bytes from the len buffer into the payload buffer. These
	// bytes are actually part of the payload.
	extraBytes := copy(buf, lenbuf[consumed:])
	if _, err := io.ReadFull(src, buf[extraBytes:]); err != nil {
		return err
	}

	// Unmarshal the payload into an "Any" protobuf, which encodes the actual
	// event.
	encodedEv := emptyAny()
	if err := proto.Unmarshal(buf, encodedEv); err != nil {
		return fmt.Errorf("failed to unmarshal 'any' protobuf message: %v", err)
	}

	var ev pb.DebugEvent
	if err := (encodedEv).UnmarshalTo(&ev); err != nil {
		return fmt.Errorf("failed to decode 'any' protobuf message: %v", err)
	}

	if e.filtering && e.allowlist[ev.Name] {
		e.filtered++
		return nil
	}

	if e.filtering && e.filtered > 0 {
		if e.filtered == 1 {
			fmt.Fprintf(out, "... filtered %d event ...\n\n", e.filtered)
		} else {
			fmt.Fprintf(out, "... filtered %d events ...\n\n", e.filtered)
		}
		e.filtered = 0
	}

	// Extract the inner event and display it. Example:
	//
	//   2017-10-04 14:35:05.316180374 -0700 PDT m=+1.132485846
	//   cloud_gvisor.MemoryUsage {
	//   total: 23822336
	//   }
	fmt.Fprintf(out, "%v\n%v {\n", time.Now(), ev.Name)
	fmt.Fprintf(out, "%v", ev.Text)
	fmt.Fprintf(out, "}\n\n")

	return nil
}

// ProcessAll reads, parses and displays all events from src. The events are
// displayed to out.
func ProcessAll(src io.Reader, filters []string, out *os.File) error {
	ep := newEventProcessor(filters)
	for {
		switch err := ep.processOne(src, out); err {
		case nil:
			continue
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}
