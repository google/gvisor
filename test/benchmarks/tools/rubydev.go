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

package tools

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// ExtractRubyTestTime extracts the test time from fastlane ruby test output.
func ExtractRubyTestTime(output string) (time.Duration, error) {
	testTime, err := extractRubyTime("Finished in ", ` \(files took`, output)
	if err != nil {
		return 0, fmt.Errorf("failed to extract test time: %v, output=\n%s", err, output)
	}
	return testTime, nil
}

// ExtractRubyLoadTime extracts the load time from fastlane ruby test output.
func ExtractRubyLoadTime(output string) (time.Duration, error) {
	loadTime, err := extractRubyTime(`\(files took `, ` to load\)`, output)
	if err != nil {
		return 0, fmt.Errorf("failed to extract load time: %v, output=\n%s", err, output)
	}
	return loadTime, nil
}

// extractRubyTime extracts the time from s in the format ([x] minutes [y] seconds)
// where minutes may be optional. It returns the time in seconds. No commas are
// expected in the numbers.
func extractRubyTime(prefix, suffix, s string) (time.Duration, error) {
	submatches := regexp.MustCompile(prefix + `(\d+) minute[s]? (\d+[\.]?[\d]*) second[s]?` + suffix).FindStringSubmatch(s)
	if len(submatches) == 3 {
		mins, err := strconv.ParseInt(submatches[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse minutes: %v, prefix = %q, suffix = %q", err, prefix, suffix)
		}
		secs, err := strconv.ParseFloat(submatches[2], 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse seconds: %v, prefix = %q, suffix = %q", err, prefix, suffix)
		}
		return (time.Minute * time.Duration(mins)) + time.Duration(float64(time.Second)*secs), nil
	}
	submatches = regexp.MustCompile(prefix + `(\d+[\.]?[\d]*) second[s]?` + suffix).FindStringSubmatch(s)
	if len(submatches) == 2 {
		secs, err := strconv.ParseFloat(submatches[1], 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse seconds: %v, prefix = %q, suffix = %q", err, prefix, suffix)
		}
		return time.Duration(float64(time.Second) * secs), nil
	}
	return 0, fmt.Errorf("count not find prefix = %q and suffix = %q", prefix, suffix)
}
