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

package metricsviz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// publishHTMLFn is the function to use to publish HTML.
// Can be stubbed out.
var publishHTMLFn = publishHTML

// publishHTML publishes the HTML contents to a sane file location and
// writes the path to the logger.
func publishHTML(ctx context.Context, logFn func(format string, args ...any), htmlOptions HTMLOptions, html string) error {
	// We don't use the test's temporary directory here because it is deleted at
	// the end of the test, but we want to keep the HTML around later for
	// viewing. So we just use a new temporary directory in `/tmp` here.
	const metricsDirRoot = "/tmp/gvisor_metrics"

	if err := os.MkdirAll(metricsDirRoot, 0755); err != nil {
		return fmt.Errorf("failed to create metrics directory %q: %w", metricsDirRoot, err)
	}
	dirName := htmlOptions.Title
	if firstSlash := strings.Index(htmlOptions.Title, "/"); firstSlash != -1 {
		dirName = htmlOptions.Title[:firstSlash]
	}
	benchmarkDir := filepath.Join(metricsDirRoot, slugify(dirName))
	if err := os.MkdirAll(benchmarkDir, 0755); err != nil {
		return fmt.Errorf("failed to create benchmark directory %q: %w", benchmarkDir, err)
	}
	htmlPath := filepath.Join(benchmarkDir, fmt.Sprintf("charts.%s-%s.%s.html", htmlOptions.When.Format(time.DateOnly), htmlOptions.When.Format(time.TimeOnly), slugify(htmlOptions.Title)))
	if err := os.WriteFile(htmlPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write HTML to %q: %w", htmlPath, err)
	}
	if err := os.Chmod(htmlPath, 0644); err != nil {
		return fmt.Errorf("failed to chmod %q: %w", htmlPath, err)
	}
	if htmlOptions.ContainerName == "" {
		logFn("******** METRICS CHARTS: file://%s ********", htmlPath)
	} else {
		logFn("******** METRICS CHARTS (%s): file://%s ********", htmlOptions.ContainerName, htmlPath)
	}
	return nil
}
