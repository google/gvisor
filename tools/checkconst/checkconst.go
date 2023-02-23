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

// Package checkconst checks constant values.
//
// This analyzer supports multiple annotations: checkconst, checkoffset, checksize and checkalign.
// Each of these essentially checks the value of the declared constant (or the #define'ed value in
// the case of an assembly file) against the value seen during analysis. If this does not match,
// an error is emitted with the appropriate value for that constant/offset/size/alignment.
package checkconst

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

var (
	checkconstMagic  = "\\+check(const|align|offset|size)"
	checkconstRegexp = regexp.MustCompile(checkconstMagic)
	constRegexp      = regexp.MustCompile("//\\s+" + checkconstMagic + "\\s+([A-Za-z0-9_\\.]+)\\s+([A-Za-z0-9_\\.]+)")
	defineRegexp     = regexp.MustCompile("#define\\s+[A-Za-z0-9_]+\\s+([A-Za-z0-9_]+\\s*\\+\\s*)*([x0-9]+)\\s+//\\s+" + checkconstMagic + "\\s+([A-Za-z0-9_\\.]+)\\s+([A-Za-z0-9_\\.]+)")
)

// Analyzer defines the entrypoint.
var Analyzer = &analysis.Analyzer{
	Name: "checkconst",
	Doc:  "validates basic constants",
	Run:  run,
	FactTypes: []analysis.Fact{
		(*Constants)(nil),
	},
}

// Constants contains all constant values.
type Constants struct {
	Alignments map[string]int64
	Offsets    map[string]int64
	Sizes      map[string]int64
	Values     map[string]string
}

// AFact implements analysis.Fact.AFact.
func (*Constants) AFact() {}

// walkObject walks a local object hierarchy.
func (c *Constants) walkObject(pass *analysis.Pass, parents []string, obj types.Object) {
	switch x := obj.(type) {
	case *types.Const:
		name := strings.Join(parents, ".")
		c.Values[name] = x.Val().ExactString()
	case *types.PkgName:
		// Don't walk to other packages.
	case *types.Var:
		// Add information as a field.
		bestEffort(func() {
			name := strings.Join(parents, ".")
			c.Alignments[name] = pass.TypesSizes.Alignof(x.Type())
			c.Sizes[name] = pass.TypesSizes.Sizeof(x.Type())
		})
	case *types.TypeName:
		// Skip if just an alias, or if not underlying type, or if a
		// type parameter. If it is not an alias, then it must be
		// package-local.
		typ := x.Type()
		if x.IsAlias() || typ == nil || typ.Underlying() == nil {
			break
		}
		if _, ok := typ.(*types.TypeParam); ok {
			break
		}
		// Add basic information.
		bestEffort(func() {
			name := strings.Join(parents, ".")
			c.Alignments[name] = pass.TypesSizes.Alignof(typ)
			c.Sizes[name] = pass.TypesSizes.Sizeof(typ)
		})
		// Recurse to fields if this is a definition.
		if structType, ok := typ.Underlying().(*types.Struct); ok {
			fields := make([]*types.Var, 0, structType.NumFields())
			for i := 0; i < structType.NumFields(); i++ {
				fieldObj := structType.Field(i)
				fields = append(fields, fieldObj)
				c.walkObject(pass, append(parents, fieldObj.Name()), fieldObj)
			}
			bestEffort(func() {
				offsets := pass.TypesSizes.Offsetsof(fields)
				for i, field := range fields {
					fieldName := strings.Join(append(parents, field.Name()), ".")
					c.Offsets[fieldName] = offsets[i]
				}
			})
		}
	}
}

// bestEffort is a panic/recover wrapper. This is used because the tools
// library occasionally panics due to some type parameter use, and there is
// simple or obvious way to detect these conditions. This should only be used
// when absolutely necessary.
func bestEffort(fn func()) {
	defer func() {
		recover()
	}()
	fn()
}

// walkScope recursively resolves a scope.
func (c *Constants) walkScope(pass *analysis.Pass, parents []string, scope *types.Scope) {
	for _, name := range scope.Names() {
		c.walkObject(pass, append(parents, name), scope.Lookup(name))
	}
}

// extractFacts finds all local facts.
func extractFacts(pass *analysis.Pass) {
	c := Constants{
		Alignments: make(map[string]int64),
		Offsets:    make(map[string]int64),
		Sizes:      make(map[string]int64),
		Values:     make(map[string]string),
	}

	// Accumulate all facts.
	c.walkScope(pass, make([]string, 0, 128), pass.Pkg.Scope())
	pass.ExportPackageFact(&c)
}

// findPackage finds the package by name.
func findPackage(pkg *types.Package, pkgName string) (*types.Package, error) {
	if pkgName == "." || pkgName == "" {
		return pkg, nil
	}
	// Attempt to resolve with the full path.
	for _, importedPkg := range pkg.Imports() {
		if importedPkg.Path() == pkgName {
			return importedPkg, nil
		}
	}
	// Attempt to resolve using the short name.
	for _, importedPkg := range pkg.Imports() {
		if importedPkg.Name() == pkgName {
			return importedPkg, nil
		}
	}
	return nil, fmt.Errorf("unable to locate package %q", pkgName)
}

// matchRegexp performs a regexp match with a sanity check.
func matchRegexp(pass *analysis.Pass, pos func() token.Pos, re *regexp.Regexp, text string) ([]string, bool) {
	m := re.FindStringSubmatch(text)
	if m == nil && checkconstRegexp.FindString(text) != "" {
		pass.Reportf(pos(), "potentially misformed checkconst directives")
	}
	return m, m != nil
}

// buildExpected builds the expected value.
func buildExpected(pass *analysis.Pass, pos func() token.Pos, factName, pkgName, objName string) (string, bool) {
	// First, resolve the package.
	pkg, err := findPackage(pass.Pkg, pkgName)
	if err != nil {
		pass.Reportf(pos(), "unable to resolve package %q: %v", pkgName, err)
		return "", false
	}

	// Next, read the appropriate facts.
	var (
		c  Constants
		s  string
		ok bool
	)
	if !pass.ImportPackageFact(pkg, &c) {
		pass.Reportf(pos(), "constant package facts for %q are unavailable", pkg.Path())
		return "", false
	}

	// Finally, format appropriately.
	switch factName {
	case "const":
		s, ok = c.Values[objName]
	case "align":
		if v, vOk := c.Alignments[objName]; vOk {
			s, ok = fmt.Sprintf("%d", v), true
		}
	case "offset":
		if v, vOk := c.Offsets[objName]; vOk {
			s, ok = fmt.Sprintf("%d", v), true
		}
	case "size":
		if v, vOk := c.Sizes[objName]; vOk {
			s, ok = fmt.Sprintf("%d", v), true
		}
	}
	if !ok {
		pass.Reportf(pos(), "fact of type %s unavailable for %q", factName, objName)
	}
	return s, ok
}

// checkAssembly checks assembly annotations.
func checkAssembly(pass *analysis.Pass) error {
	for _, filename := range pass.OtherFiles {
		if !strings.HasSuffix(filename, ".s") {
			continue
		}
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("unable to read assembly file: %w", err)
		}
		// This uses the technique to report issues for assembly files
		// as described by the Go documentation:
		// https://pkg.go.dev/golang.org/x/tools/go/analysis#hdr-Pass
		tf := pass.Fset.AddFile(filename, -1, len(content))
		tf.SetLinesForContent(content)
		lines := strings.Split(string(content), "\n")
		for lineNumber, lineContent := range lines {
			// N.B. This is not evaluated except lazily, since it
			// will generate errors to attempt to grab the position
			// at the end of input. Just avoid it.
			pos := func() token.Pos {
				return tf.LineStart(lineNumber + 1)
			}
			m, ok := matchRegexp(pass, pos, defineRegexp, lineContent)
			if !ok {
				continue // Already reported, if needed.
			}
			newValue, ok := buildExpected(pass, pos, m[3], m[4], m[5])
			if !ok {
				continue // Already reported.
			}
			// Convert our internal string to the given value. This essentially
			// canonicalises the literal string provided in the assembly.
			v, err := strconv.ParseInt(m[2], 10, 64)
			if err == nil && fmt.Sprintf("%v", v) != newValue {
				pass.Reportf(pos(), "got value %v, wanted %q", v, newValue)
				continue
			} else if err != nil && m[2] != newValue {
				pass.Reportf(pos(), "got value %q, wanted %q", m[2], newValue)
				continue
			}
		}
	}
	return nil
}

// checkConsts walks all package-level const objects.
func checkConsts(pass *analysis.Pass) error {
	for _, f := range pass.Files {
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.CONST {
				continue
			}
			findComments := func(vs *ast.ValueSpec) []*ast.Comment {
				comments := make([]*ast.Comment, 0)
				if d.Doc != nil {
					// Include any formally associated doc from the block.
					comments = append(comments, d.Doc.List...)
				}
				if vs.Doc != nil {
					// Include any formally associated comments from the value.
					comments = append(comments, vs.Doc.List...)
				}
				for _, cg := range f.Comments {
					for _, c := range cg.List {
						// Include any comments that appear on the same line
						// as the value spec itself, which are not doc comments.
						specPosition := pass.Fset.Position(vs.Pos())
						commentPosition := pass.Fset.Position(c.Pos())
						if specPosition.Line == commentPosition.Line && specPosition.Column < commentPosition.Column {
							comments = append(comments, c)
						}
					}
				}
				return comments
			}
			for _, spec := range d.Specs {
				vs := spec.(*ast.ValueSpec)
				var (
					expectedValue string
					expectedSet   bool
				)
				for _, l := range findComments(vs) {
					m, ok := matchRegexp(pass, l.Pos, constRegexp, l.Text)
					if !ok {
						continue // Already reported, if needed.
					}
					newValue, ok := buildExpected(pass, l.Pos, m[1], m[2], m[3])
					if ok {
						if expectedSet && newValue != expectedValue {
							pass.Reportf(l.Pos(), "multiple conflicting values")
							continue
						}
						expectedValue = newValue
						expectedSet = true
					}
				}
				if !expectedSet {
					continue // Nothing was set.
				}
				// Format the expression.
				var buf bytes.Buffer
				for _, value := range vs.Values {
					if err := format.Node(&buf, pass.Fset, value); err != nil {
						pass.Reportf(value.Pos(), "unable to format expression: %v", err)
						continue
					}
					if s := string(buf.Bytes()); s != expectedValue {
						pass.Reportf(value.Pos(), "got value %q, wanted %q", s, expectedValue)
						continue
					}
				}
			}
		}
	}
	return nil
}

func run(pass *analysis.Pass) (any, error) {
	// Extract all local facts. This is done against the compiled objects,
	// rather than the source-level analysis, which is done below.
	extractFacts(pass)

	// Check the local package.
	if err := checkConsts(pass); err != nil {
		return nil, err
	}
	if err := checkAssembly(pass); err != nil {
		return nil, err
	}
	return nil, nil
}
