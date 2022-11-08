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

// Package null defines a seccheck.Sink that does nothing with the trace
// points, akin to /dev/null.
package null

import (
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
)

const name = "null"

func init() {
	seccheck.RegisterSink(seccheck.SinkDesc{
		Name: name,
		New:  new,
	})
}

// null is a checker that does nothing with the trace points.
type null struct {
	seccheck.SinkDefaults
}

var _ seccheck.Sink = (*null)(nil)

func new(_ map[string]any, _ *fd.FD) (seccheck.Sink, error) {
	return &null{}, nil
}

func (*null) Name() string {
	return name
}
