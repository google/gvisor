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

package nogo

import (
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/tools/go/analysis"
)

type matcher interface {
	ShouldReport(d analysis.Diagnostic, fs *token.FileSet) bool
}

// pathRegexps filters explicit paths.
type pathRegexps struct {
	expr []*regexp.Regexp

	// include, if true, indicates that paths matching any regexp in expr
	// match.
	//
	// If false, paths matching no regexps in expr match.
	include bool
}

// buildRegexps builds a list of regular expressions.
//
// This will panic on error.
func buildRegexps(prefix string, args ...string) []*regexp.Regexp {
	result := make([]*regexp.Regexp, 0, len(args))
	for _, arg := range args {
		result = append(result, regexp.MustCompile(filepath.Join(prefix, arg)))
	}
	return result
}

// ShouldReport implements matcher.ShouldReport.
func (p *pathRegexps) ShouldReport(d analysis.Diagnostic, fs *token.FileSet) bool {
	fullPos := fs.Position(d.Pos).String()
	for _, path := range p.expr {
		if path.MatchString(fullPos) {
			return p.include
		}
	}
	return !p.include
}

// internalExcluded excludes specific internal paths.
func internalExcluded(paths ...string) *pathRegexps {
	return &pathRegexps{
		expr:    buildRegexps(internalPrefix, paths...),
		include: false,
	}
}

// excludedExcluded excludes specific external paths.
func externalExcluded(paths ...string) *pathRegexps {
	return &pathRegexps{
		expr:    buildRegexps(externalPrefix, paths...),
		include: false,
	}
}

// internalMatches returns a path matcher for internal packages.
func internalMatches() *pathRegexps {
	return &pathRegexps{
		expr:    buildRegexps(internalPrefix, ".*"),
		include: true,
	}
}

// resultExcluded excludes explicit message contents.
type resultExcluded []string

// ShouldReport implements matcher.ShouldReport.
func (r resultExcluded) ShouldReport(d analysis.Diagnostic, _ *token.FileSet) bool {
	for _, str := range r {
		if strings.Contains(d.Message, str) {
			return false
		}
	}
	return true // Not excluded.
}

// andMatcher is a composite matcher.
type andMatcher struct {
	first  matcher
	second matcher
}

// ShouldReport implements matcher.ShouldReport.
func (a *andMatcher) ShouldReport(d analysis.Diagnostic, fs *token.FileSet) bool {
	return a.first.ShouldReport(d, fs) && a.second.ShouldReport(d, fs)
}

// and is a syntactic convension for andMatcher.
func and(first matcher, second matcher) *andMatcher {
	return &andMatcher{
		first:  first,
		second: second,
	}
}

// anyMatcher matches everything.
type anyMatcher struct{}

// ShouldReport implements matcher.ShouldReport.
func (anyMatcher) ShouldReport(analysis.Diagnostic, *token.FileSet) bool {
	return true
}

// alwaysMatches returns an anyMatcher instance.
func alwaysMatches() anyMatcher {
	return anyMatcher{}
}

// neverMatcher will never match.
type neverMatcher struct{}

// ShouldReport implements matcher.ShouldReport.
func (neverMatcher) ShouldReport(analysis.Diagnostic, *token.FileSet) bool {
	return false
}

// disableMatches returns a neverMatcher instance.
func disableMatches() neverMatcher {
	return neverMatcher{}
}
