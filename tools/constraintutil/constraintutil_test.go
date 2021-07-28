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

package constraintutil

import (
	"go/build/constraint"
	"testing"
)

func TestFileParsing(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		expr string
	}{
		{
			name: "Empty",
		},
		{
			name: "NoConstraint",
			data: "// copyright header\n\npackage main",
		},
		{
			name: "ConstraintOnFirstLine",
			data: "//go:build amd64\n#include \"textflag.h\"",
			expr: "amd64",
		},
		{
			name: "ConstraintAfterSlashSlashComment",
			data: "// copyright header\n\n//go:build linux\n\npackage newlib",
			expr: "linux",
		},
		{
			name: "ConstraintAfterSlashStarComment",
			data: "/*\ncopyright header\n*/\n\n//go:build !race\n\npackage oldlib",
			expr: "!race",
		},
		{
			name: "ConstraintInSlashSlashComment",
			data: "// blah blah //go:build windows",
		},
		{
			name: "ConstraintInSlashStarComment",
			data: "/*\n//go:build windows\n*/",
		},
		{
			name: "ConstraintAfterPackageClause",
			data: "package oops\n//go:build race",
		},
		{
			name: "ConstraintAfterCppInclude",
			data: "#include \"textflag.h\"\n//go:build arm64",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, err := FromString(test.data)
			if err != nil {
				t.Fatalf("FromString(%q) failed: %v", test.data, err)
			}
			if e == nil {
				if len(test.expr) != 0 {
					t.Errorf("FromString(%q): got no constraint, wanted %q", test.data, test.expr)
				}
			} else {
				got := e.String()
				if len(test.expr) == 0 {
					t.Errorf("FromString(%q): got %q, wanted no constraint", test.data, got)
				} else if got != test.expr {
					t.Errorf("FromString(%q): got %q, wanted %q", test.data, got, test.expr)
				}
			}
		})
	}
}

func TestCombine(t *testing.T) {
	for _, test := range []struct {
		name string
		in   []string
		out  string
	}{
		{
			name: "0",
		},
		{
			name: "1",
			in:   []string{"amd64 || arm64"},
			out:  "amd64 || arm64",
		},
		{
			name: "2",
			in:   []string{"amd64", "amd64 && linux"},
			out:  "amd64 && amd64 && linux",
		},
		{
			name: "3",
			in:   []string{"amd64", "amd64 || arm64", "amd64 || riscv64"},
			out:  "amd64 && (amd64 || arm64) && (amd64 || riscv64)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			inexprs := make([]constraint.Expr, 0, len(test.in))
			for _, estr := range test.in {
				line := "//go:build " + estr
				e, err := constraint.Parse(line)
				if err != nil {
					t.Fatalf("constraint.Parse(%q) failed: %v", line, err)
				}
				inexprs = append(inexprs, e)
			}
			outexpr := Combine(inexprs)
			if outexpr == nil {
				if len(test.out) != 0 {
					t.Errorf("Combine(%v): got no constraint, wanted %q", test.in, test.out)
				}
			} else {
				got := outexpr.String()
				if len(test.out) == 0 {
					t.Errorf("Combine(%v): got %q, wanted no constraint", test.in, got)
				} else if got != test.out {
					t.Errorf("Combine(%v): got %q, wanted %q", test.in, got, test.out)
				}
			}
		})
	}
}
