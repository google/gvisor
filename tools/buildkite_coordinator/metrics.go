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

package main

import (
	"context"
	"fmt"
	"time"

	monitoring "google.golang.org/api/monitoring/v3"
)

// reservedJobsMetric is the Cloud Monitoring metric of the number of jobs
// reserved, with the queue as the "queue" label.
const reservedJobsMetric = "custom.googleapis.com/buildkite_coordinator/reserved_jobs"

// publishReservedJobs publishes the number of reserved jobs of each queue to
// the given project.
func publishReservedJobs(ctx context.Context, svc *monitoring.Service, project string, counts map[string]uint) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	series := make([]*monitoring.TimeSeries, 0, len(counts))
	for queue, count := range counts {
		value := int64(count)
		series = append(series, &monitoring.TimeSeries{
			Metric: &monitoring.Metric{
				Type:   reservedJobsMetric,
				Labels: map[string]string{"queue": queue},
			},
			Resource: &monitoring.MonitoredResource{
				Type:   "global",
				Labels: map[string]string{"project_id": project},
			},
			Points: []*monitoring.Point{{
				Interval: &monitoring.TimeInterval{EndTime: now},
				Value:    &monitoring.TypedValue{Int64Value: &value},
			}},
		})
	}
	req := &monitoring.CreateTimeSeriesRequest{TimeSeries: series}
	if _, err := svc.Projects.TimeSeries.Create("projects/"+project, req).Context(ctx).Do(); err != nil {
		return fmt.Errorf("failed to publish %v: %w", reservedJobsMetric, err)
	}
	return nil
}
