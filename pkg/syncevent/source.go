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

package syncevent

// Source represents an event source.
type Source interface {
	// SubscribeEvents causes the Source to notify the given Receiver of the
	// given subset of events.
	//
	// Preconditions:
	//	* r != nil.
	//	* The ReceiverCallback for r must not take locks that are ordered
	//		prior to the Source; for example, it cannot call any Source
	//		methods.
	SubscribeEvents(r *Receiver, filter Set) SubscriptionID

	// UnsubscribeEvents causes the Source to stop notifying the Receiver
	// subscribed by a previous call to SubscribeEvents that returned the given
	// SubscriptionID.
	//
	// Preconditions: UnsubscribeEvents may be called at most once for any
	// given SubscriptionID.
	UnsubscribeEvents(id SubscriptionID)
}

// SubscriptionID identifies a call to Source.SubscribeEvents.
type SubscriptionID uint64

// UnsubscribeAndAck is a convenience function that unsubscribes r from the
// given events from src and also clears them from r.
func UnsubscribeAndAck(src Source, r *Receiver, filter Set, id SubscriptionID) {
	src.UnsubscribeEvents(id)
	r.Ack(filter)
}

// NoopSource implements Source by never sending events to subscribed
// Receivers.
type NoopSource struct{}

// SubscribeEvents implements Source.SubscribeEvents.
func (NoopSource) SubscribeEvents(*Receiver, Set) SubscriptionID {
	return 0
}

// UnsubscribeEvents implements Source.UnsubscribeEvents.
func (NoopSource) UnsubscribeEvents(SubscriptionID) {
}

// See Broadcaster for a non-noop implementations of Source.
