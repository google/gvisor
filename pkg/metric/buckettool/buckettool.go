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

// buckettool prints buckets for distribution metrics.
package main

import (
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/runsc/flag"
)

var (
	typeFlag             = flag.String("type", "duration", "Type of the bucketer: 'duration' or 'exponential'")
	numFiniteBucketsFlag = flag.Int("num_finite_buckets", 8, "Number of finite buckets")
	minDurationFlag      = flag.Duration("min_duration", 5*time.Millisecond, "For -type=duration: Minimum duration")
	maxDurationFlag      = flag.Duration("max_duration", 10*time.Minute, "For -type=duration: Maximum duration")
	widthFlag            = flag.Uint64("exponential_width", 5, "For -type=exponential: Initial bucket width")
	scaleFlag            = flag.Float64("exponential_scale", 10, "For -type=exponential: Scaling factor")
	growthFlag           = flag.Float64("exponential_growth", 4, "For -type=exponential: Exponential growth factor")
)

func exitf(format string, values ...any) {
	log.Warningf(format, values...)
	os.Exit(1)
}

func main() {
	flag.Parse()
	var bucketer metric.Bucketer
	var formatVal func(int64) string
	switch *typeFlag {
	case "duration":
		bucketer = metric.NewDurationBucketer(*numFiniteBucketsFlag, *minDurationFlag, *maxDurationFlag)
		formatVal = func(val int64) string {
			return time.Duration(val).String()
		}
	case "exponential":
		bucketer = metric.NewExponentialBucketer(*numFiniteBucketsFlag, *widthFlag, *scaleFlag, *growthFlag)
		formatVal = func(val int64) string {
			return fmt.Sprintf("%v", val)
		}
	default:
		exitf("Invalid -type: %s", *typeFlag)
	}
	fmt.Printf("Number of finite buckets: %d\n", bucketer.NumFiniteBuckets())
	fmt.Printf("Number of total buckets:  %d\n", bucketer.NumFiniteBuckets()+2)
	fmt.Printf("> Underflow bucket: (-inf; %s)\n", formatVal(bucketer.LowerBound(0)))
	for b := 0; b < bucketer.NumFiniteBuckets(); b++ {
		fmt.Printf("> Bucket index %d: [%s, %s). (Middle: %s)\n", b, formatVal(bucketer.LowerBound(b)), formatVal(bucketer.LowerBound(b+1)), formatVal((bucketer.LowerBound(b)+bucketer.LowerBound(b+1))/2))
	}
	fmt.Printf("> Overflow bucket: [%s; +inf)\n", formatVal(bucketer.LowerBound(bucketer.NumFiniteBuckets())))
}
