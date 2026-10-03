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

package control

import (
	"errors"
	"fmt"

	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/urpc"
)

// EventsOpts are the arguments for eventchannel-related commands.
type EventsOpts struct {
	urpc.FilePayload
}

// Events is the control server state for eventchannel-related commands.
type Events struct {
	emitter eventchannel.Emitter
}

// AttachDebugEmitter receives a connected unix domain socket FD from the client
// and establishes it as a new emitter for the sentry eventchannel. Each event is
// written as a DebugEvent holding the event's name and its text format. Any
// existing emitters are replaced on a subsequent attach.
func (e *Events) AttachDebugEmitter(o *EventsOpts, _ *struct{}) error {
	return e.attach(o, eventchannel.DebugEmitterFrom)
}

// AttachRawEmitter receives a connected unix domain socket FD from the client
// and establishes it as a new emitter for the sentry eventchannel. Each event is
// written as an Any message holding the event itself, in the framing of
// eventchannel.SocketEmitter. Any existing emitters are replaced on a
// subsequent attach.
func (e *Events) AttachRawEmitter(o *EventsOpts, _ *struct{}) error {
	return e.attach(o, nil)
}

// attach establishes the socket FD in o as the emitter of e, wrapped by wrap
// if it is not nil.
func (e *Events) attach(o *EventsOpts, wrap func(eventchannel.Emitter) eventchannel.Emitter) error {
	if len(o.FilePayload.Files) < 1 {
		return errors.New("no output writer provided")
	}

	sock, err := o.ReleaseFD(0)
	if err != nil {
		return err
	}
	sockFD := sock.Release()

	// SocketEmitter takes ownership of sockFD.
	emitter, err := eventchannel.SocketEmitter(sockFD)
	if err != nil {
		return fmt.Errorf("failed to create SocketEmitter for FD %d: %v", sockFD, err)
	}
	if wrap != nil {
		emitter = wrap(emitter)
	}

	// If there is already an emitter, stop sending events to it and close it.
	if e.emitter != nil {
		eventchannel.RemoveEmitter(e.emitter)
		e.emitter.Close()
	}

	e.emitter = emitter

	// Register the new stream destination.
	eventchannel.AddEmitter(e.emitter)
	return nil
}
