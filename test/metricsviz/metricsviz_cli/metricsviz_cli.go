// Copyright 2024 The gVisor Authors.
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

// metricsviz_cli visualizes metrics from profiling metrics logs.
package main

import (
	"context"
	"fmt"
	"os"

	"gvisor.dev/gvisor/test/metricsviz"
)

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s /path/to/profiling_metrics.log\n", os.Args[0])
		os.Exit(2)
	}
	for _, arg := range os.Args[1:] {
		if err := metricsviz.FromFile(ctx, arg, func(format string, args ...any) {
			fmt.Fprintf(os.Stdout, format+"\n", args...)
		}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
