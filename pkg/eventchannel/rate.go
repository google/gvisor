// Copyright 2019 The gVisor Authors.
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
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
)

// rateLimitedEmitter wraps an emitter and limits events to the given limits.
// Events that would exceed the limit are discarded.
type rateLimitedEmitter struct {
	inner   Emitter
	limiter *rate.Limiter
}

// RateLimitedEmitterFrom creates a new event channel emitter that wraps the
// existing emitter and enforces rate limits. The limits are imposed via a
// token bucket, with `maxRate` events per second, with burst size of `burst`
// events. See the golang.org/x/time/rate package and
// https://en.wikipedia.org/wiki/Token_bucket for more information about token
// buckets generally.
func RateLimitedEmitterFrom(inner Emitter, maxRate float64, burst int) Emitter {
	return &rateLimitedEmitter{
		inner:   inner,
		limiter: rate.NewLimiter(rate.Limit(maxRate), burst),
	}
}

// Emit implements EventEmitter.Emit.
func (rle *rateLimitedEmitter) Emit(msg proto.Message) (bool, error) {
	if !rle.limiter.Allow() {
		// Drop event.
		return false, nil
	}
	return rle.inner.Emit(msg)
}

// Close implements EventEmitter.Close.
func (rle *rateLimitedEmitter) Close() error {
	return rle.inner.Close()
}
