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

// Functions to register Go runtime metrics, from the runtime/metrics package
// added in Go 1.16.

// +build go1.16

package metric

import (
	"fmt"
	"runtime/metrics"
	"sync"

	pb "gvisor.dev/gvisor/pkg/metric/metric_go_proto"
)

var (
	runtimeOnce sync.Once
	runtimeDesc map[string]metrics.Description
)

func runtimeLookup(name string) (metrics.Description, bool) {
	runtimeOnce.Do(func() {
		desc := metrics.All()
		runtimeDesc = make(map[string]metrics.Description, len(desc))
		for _, d := range desc {
			runtimeDesc[d.Name] = d
		}
	})
	d, ok := runtimeDesc[name]
	return d, ok
}

// RuntimeUint64 is a Go runtime metric from package runtime/metrics, of kind
// metrics.KindUint64.
type RuntimeUint64 struct {
	name string
}

// Value returns the current value of the metric.
func (r *RuntimeUint64) Value() uint64 {
	samples := []metrics.Sample{{Name: r.name}}
	metrics.Read(samples)
	return samples[0].Value.Uint64()
}

// NewRuntimeUint64Metrics creates and registers a new metric called 'name'
// from the runtime metric called 'rtname'.
//
// NewRuntimeUint64Metrics returns an error if 'rtname' does not exist or is
// not KindUint64.
func NewRuntimeUint64Metric(name, rtname string) (*RuntimeUint64, error) {
	d, ok := runtimeLookup(rtname)
	if !ok {
		return nil, fmt.Errorf("runtime metric %q does not exist", rtname)
	}

	if d.Kind != metrics.KindUint64 {
		return nil, fmt.Errorf("runtime metric %q has incorrect kind %s", rtname, d.Kind)
	}

	r := &RuntimeUint64{
		name: rtname,
	}
	return r, RegisterCustomUint64Metric(name, d.Cumulative, false /* sync */, pb.MetricMetadata_UNITS_NONE, d.Description, r.Value)
}

// MustCreateNewRuntimeUint64Metrics calls NewRuntimeUint64Metric and panics if
// it returns an error.
func MustCreateNewRuntimeUint64Metric(name, rtname string) *RuntimeUint64 {
	r, err := NewRuntimeUint64Metric(name, rtname)
	if err != nil {
		panic(fmt.Sprintf("Unable to create runtime metric %q -> %q: %v", name, rtname, err))
	}
	return r
}
