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
// charecters in b.ReportMetric calls.
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
// it as a set of Parameters.
// Example: BenchmarkRuby/server_threads.1/doc_size.16KB-6
// The parameter part of this benchmark is:
// "server_threads.1/doc_size.16KB" (BenchmarkRuby is the name, and 6 is GOMAXPROCS)
// This function will return a slice with two parameters ->
// {Name: server_threads, Value: 1}, {Name: doc_size, Value: 16KB}
func NameToParameters(name string) ([]*Parameter, error) {
	var params []*Parameter
	for _, cond := range strings.Split(name, "/") {
		cs := strings.Split(cond, ".")
		switch len(cs) {
		case 1:
			params = append(params, &Parameter{Name: cond, Value: cond})
		case 2:
			params = append(params, &Parameter{Name: cs[0], Value: cs[1]})
		default:
			return nil, fmt.Errorf("failed to parse param: %s", cond)
		}
	}
	return params, nil
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
	nameUnit := strings.Split(metric, ".")
	if len(nameUnit) != 2 {
		return nil, fmt.Errorf("failed to parse metric: %s", metric)
	}
	return &Metric{Name: nameUnit[0], Unit: nameUnit[1], Sample: sample}, nil
}
