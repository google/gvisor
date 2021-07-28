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

// Package constraintutil provides utilities for working with Go build
// constraints.
package constraintutil

import (
	"bufio"
	"bytes"
	"fmt"
	"go/build/constraint"
	"io"
	"os"
	"strings"
)

// FromReader extracts the build constraint from the Go source or assembly file
// whose contents are read by r.
func FromReader(r io.Reader) (constraint.Expr, error) {
	// See go/build.parseFileHeader() for the "official" logic that this is
	// derived from.
	const (
		slashStar     = "/*"
		starSlash     = "*/"
		gobuildPrefix = "//go:build"
	)
	s := bufio.NewScanner(r)
	var (
		inSlashStar = false // between /* and */
		haveGobuild = false
		e           constraint.Expr
	)
Lines:
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if !inSlashStar && constraint.IsGoBuild(string(line)) {
			if haveGobuild {
				return nil, fmt.Errorf("multiple go:build directives")
			}
			haveGobuild = true
			var err error
			e, err = constraint.Parse(string(line))
			if err != nil {
				return nil, err
			}
		}
	ThisLine:
		for len(line) > 0 {
			if inSlashStar {
				if i := bytes.Index(line, []byte(starSlash)); i >= 0 {
					inSlashStar = false
					line = bytes.TrimSpace(line[i+len(starSlash):])
					continue ThisLine
				}
				continue Lines
			}
			if bytes.HasPrefix(line, []byte("//")) {
				continue Lines
			}
			// Note that if /* appears in the line, but not at the beginning,
			// then the line is still non-empty, so skipping this and
			// terminating below is correct.
			if bytes.HasPrefix(line, []byte(slashStar)) {
				inSlashStar = true
				line = bytes.TrimSpace(line[len(slashStar):])
				continue ThisLine
			}
			// A non-empty non-comment line terminates scanning for go:build.
			break Lines
		}
	}
	return e, s.Err()
}

// FromString extracts the build constraint from the Go source or assembly file
// containing the given data. If no build constraint applies to the file, it
// returns nil.
func FromString(str string) (constraint.Expr, error) {
	return FromReader(strings.NewReader(str))
}

// FromFile extracts the build constraint from the Go source or assembly file
// at the given path. If no build constraint applies to the file, it returns
// nil.
func FromFile(path string) (constraint.Expr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return FromReader(f)
}

// Combine returns a constraint.Expr that evaluates to true iff all expressions
// in es evaluate to true. If es is empty, Combine returns nil.
//
// Preconditions: All constraint.Exprs in es are non-nil.
func Combine(es []constraint.Expr) constraint.Expr {
	switch len(es) {
	case 0:
		return nil
	case 1:
		return es[0]
	default:
		a := &constraint.AndExpr{es[0], es[1]}
		for i := 2; i < len(es); i++ {
			a = &constraint.AndExpr{a, es[i]}
		}
		return a
	}
}

// CombineFromFiles returns a build constraint expression that evaluates to
// true iff the build constraints from all of the given Go source or assembly
// files evaluate to true. If no build constraints apply to any of the given
// files, it returns nil.
func CombineFromFiles(paths []string) (constraint.Expr, error) {
	var es []constraint.Expr
	for _, path := range paths {
		e, err := FromFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read build constraints from %q: %v", path, err)
		}
		if e != nil {
			es = append(es, e)
		}
	}
	return Combine(es), nil
}

// Lines returns a string containing build constraint directives for the given
// constraint.Expr, including two trailing newlines, as appropriate for a Go
// source or assembly file. At least a go:build directive will be emitted; if
// the constraint is expressible using +build directives as well, then +build
// directives will also be emitted.
//
// If e is nil, Lines returns the empty string.
func Lines(e constraint.Expr) string {
	if e == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("//go:build ")
	b.WriteString(e.String())
	b.WriteByte('\n')

	if pblines, err := constraint.PlusBuildLines(e); err == nil {
		for _, line := range pblines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	b.WriteByte('\n')
	return b.String()
}
