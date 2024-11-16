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
	"strings"
	"testing"
)

// Parameter is a test parameter.
type Parameter struct {
	Name  string
	Value string
}

// Output is parsed and split by these values. Make them illegal in input methods.
// We are constrained on what characters these can be by 1) docker's allowable
// container names, 2) golang allowable benchmark names, and 3) golangs allowable
// characters in b.ReportMetric calls.
var illegalChars = regexp.MustCompile(`[/\.]`)

// ParametersToName joins parameters into a string format for parsing.
// It is meant to be used for t.Run() calls in benchmark tools.
func ParametersToName(params ...Parameter) (string, error) {
	var strs []string
	for _, param := range params {
		if illegalChars.MatchString(param.Name) || illegalChars.MatchString(param.Value) {
			return "", fmt.Errorf("params Name: %q and Value: %q cannot container '.' or '/'", param.Name, param.Value)
		}
		strs = append(strs, strings.Join([]string{param.Name, param.Value}, "."))
	}
	return strings.Join(strs, "/"), nil
}

// NameToParameters parses the string created by ParametersToName and returns
// the name components and parameters contained within.
// The separator between the name and value may either be '.' or '='.
//
// Example: "BenchmarkRuby/SubTest/LevelTwo/server_threads.1/doc_size.16KB-6"
// The parameter part of this benchmark is "server_threads.1/doc_size.16KB",
// whereas "BenchmarkRuby/SubTest/LevelTwo" is the name, and the "-6" suffix is
// GOMAXPROCS (optional, may be omitted).
// This function will return a slice of the name components of the benchmark:
//
//	[
//	  "BenchmarkRuby",
//	  "SubTest",
//	  "LevelTwo",
//	]
//
// and a slice of the parameters:
//
//	[
//	  {Name: "server_threads", Value: "1"},
//	  {Name: "doc_size", Value: "16KB"},
//	  {Name: "GOMAXPROCS", Value: "6"},
//	]
//
// (and a nil error).
func NameToParameters(name string) ([]string, []*Parameter, error) {
	var params []*Parameter
	var separator string
	switch {
	case strings.IndexRune(name, '.') != -1 && strings.IndexRune(name, '=') != -1:
		return nil, nil, fmt.Errorf("ambiguity while parsing parameters from benchmark name %q: multiple types of parameter separators are present", name)
	case strings.IndexRune(name, '.') != -1:
		separator = "."
	case strings.IndexRune(name, '=') != -1:
		separator = "="
	default:
		// No separator; use '=' which we know is not present in the name,
		// but we still need to process the name (even if unparameterized) in
		// order to possibly extract GOMAXPROCS.
		separator = "="
	}
	var nameComponents []string
	var firstParameterCond string
	var goMaxProcs *Parameter
	split := strings.Split(name, "/")
	for i, cond := range split {
		if isLast := i == len(split)-1; isLast {
			// On the last component, if it contains a dash, it is a GOMAXPROCS value.
			if dashSplit := strings.Split(cond, "-"); len(dashSplit) >= 2 {
				goMaxProcs = &Parameter{Name: "GOMAXPROCS", Value: dashSplit[len(dashSplit)-1]}
				cond = strings.Join(dashSplit[:len(dashSplit)-1], "-")
			}
		}
		cs := strings.Split(cond, separator)
		switch len(cs) {
		case 1:
			if firstParameterCond != "" {
				return nil, nil, fmt.Errorf("failed to parse params from %q: a non-parametrized component %q was found after a parametrized one %q", name, cond, firstParameterCond)
			}
			nameComponents = append(nameComponents, cond)
		case 2:
			if firstParameterCond == "" {
				firstParameterCond = cond
			}
			params = append(params, &Parameter{Name: cs[0], Value: cs[1]})
		default:
			return nil, nil, fmt.Errorf("failed to parse params from %q: %s", name, cond)
		}
	}
	if goMaxProcs != nil {
		// GOMAXPROCS should always be last in order to match the ordering of the
		// benchmark name.
		params = append(params, goMaxProcs)
	}
	return nameComponents, params, nil
}

// ReportCustomMetric reports a metric in a set format for parsing.
func ReportCustomMetric(b *testing.B, value float64, name, unit string) {
	if illegalChars.MatchString(name) || illegalChars.MatchString(unit) {
		b.Fatalf("name: %q and unit: %q cannot contain '/' or '.'", name, unit)
	}
	nameUnit := strings.Join([]string{name, unit}, ".")
	b.ReportMetric(value, nameUnit)
}

// Metric holds metric data parsed from a string based on the format
// ReportMetric.
type Metric struct {
	Name   string
	Unit   string
	Sample float64
}

// ParseCustomMetric parses a metric reported with ReportCustomMetric.
func ParseCustomMetric(value, metric string) (*Metric, error) {
	sample, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse value: %v", err)
	}
	separators := []rune{'-', '.'}
	var separator string
	for _, sep := range separators {
		if strings.ContainsRune(metric, sep) {
			if separator != "" {
				return nil, fmt.Errorf("failed to parse metric: ambiguous unit separator: %q (is the separator %q or %q?)", metric, separator, string(sep))
			}
			separator = string(sep)
		}
	}
	var name, unit string
	switch separator {
	case "":
		unit = metric
	default:
		components := strings.Split(metric, separator)
		name, unit = strings.Join(components[:len(components)-1], ""), components[len(components)-1]
	}
	// Normalize some unit names to benchstat defaults.
	switch unit {
	case "":
		return nil, fmt.Errorf("failed to parse metric %q: no unit specified", metric)
	case "s":
		unit = "sec"
	case "nanos":
		unit = "ns"
	case "byte":
		unit = "B"
	case "bit":
		unit = "b"
	default:
		// Otherwise, leave unit as-is.
	}
	// If the metric name is unspecified, it can sometimes be inferred from
	// the unit.
	if name == "" {
		switch unit {
		case "sec":
			name = "duration"
		case "req/sec", "tok/sec":
			name = "throughput"
		case "B/sec":
			name = "bandwidth"
		default:
			return nil, fmt.Errorf("failed to parse metric %q: ambiguous metric name, please format the unit as 'name.unit' or 'name-unit'", metric)
		}
	}
	return &Metric{Name: name, Unit: unit, Sample: sample}, nil
}
