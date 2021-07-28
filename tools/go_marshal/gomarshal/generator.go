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

// Package gomarshal implements the go_marshal code generator. See README.md.
package gomarshal

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"

	"gvisor.dev/gvisor/tools/constraintutil"
)

// List of identifiers we use in generated code that may conflict with a
// similarly-named source identifier. Abort gracefully when we see these to
// avoid potentially confusing compilation failures in generated code.
//
// This only applies to import aliases at the moment. All other identifiers
// are qualified by a receiver argument, since they're struct fields.
//
// All recievers are single letters, so we don't allow import aliases to be a
// single letter.
var badIdents = []string{
	"addr", "blk", "buf", "cc", "dst", "dsts", "count", "err", "hdr", "idx",
	"inner", "length", "limit", "ptr", "size", "src", "srcs", "val",
	// All single-letter identifiers.
}

// Constructed fromt badIdents in init().
var badIdentsMap map[string]struct{}

func init() {
	badIdentsMap = make(map[string]struct{})
	for _, ident := range badIdents {
		badIdentsMap[ident] = struct{}{}
	}
}

// Generator drives code generation for a single invocation of the go_marshal
// utility.
//
// The Generator holds arguments passed to the tool, and drives parsing,
// processing and code Generator for all types marked with +marshal declared in
// the input files.
//
// See Generator.run() as the entry point.
type Generator struct {
	// Paths to input go source files.
	inputs []string
	// Output file to write generated go source.
	output *os.File
	// Output file to write generated tests.
	outputTest *os.File
	// Output file to write unconditionally generated tests.
	outputTestUC *os.File
	// Package name for the generated file.
	pkg string
	// Set of extra packages to import in the generated file.
	imports *importTable
}

// NewGenerator creates a new code Generator.
func NewGenerator(srcs []string, out, outTest, outTestUnconditional, pkg string, imports []string) (*Generator, error) {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("couldn't open output file %q: %w", out, err)
	}
	fTest, err := os.OpenFile(outTest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("couldn't open test output file %q: %w", out, err)
	}
	fTestUC, err := os.OpenFile(outTestUnconditional, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("couldn't open unconditional test output file %q: %w", out, err)
	}
	g := Generator{
		inputs:       srcs,
		output:       f,
		outputTest:   fTest,
		outputTestUC: fTestUC,
		pkg:          pkg,
		imports:      newImportTable(),
	}
	for _, i := range imports {
		// All imports on the extra imports list are unconditionally marked as
		// used, so that they're always added to the generated code.
		g.imports.add(i).markUsed()
	}

	// The following imports may or may not be used by the generated code,
	// depending on what's required for the target types. Don't mark these as
	// used by default.
	g.imports.add("io")
	g.imports.add("reflect")
	g.imports.add("runtime")
	g.imports.add("unsafe")
	g.imports.add("gvisor.dev/gvisor/pkg/gohacks")
	g.imports.add("gvisor.dev/gvisor/pkg/hostarch")
	g.imports.add("gvisor.dev/gvisor/pkg/marshal")
	return &g, nil
}

// writeHeader writes the header for the generated source file. The header
// includes the package name, package level comments and import statements.
func (g *Generator) writeHeader() error {
	var b sourceBuffer
	b.emit("// Automatically generated marshal implementation. See tools/go_marshal.\n\n")

	bcexpr, err := constraintutil.CombineFromFiles(g.inputs)
	if err != nil {
		return err
	}
	if bcexpr != nil {
		// Emit build constraints.
		b.emit("// If there are issues with build constraint aggregation, see\n")
		b.emit("// tools/go_marshal/gomarshal/generator.go:writeHeader(). The constraints here\n")
		b.emit("// come from the input set of files used to generate this file. This input set\n")
		b.emit("// is filtered based on pre-defined file suffixes related to build constraints,\n")
		b.emit("// see tools/defs.bzl:calculate_sets().\n\n")
		b.emit(constraintutil.Lines(bcexpr))
	}

	// Package header.
	b.emit("package %s\n\n", g.pkg)
	if err := b.write(g.output); err != nil {
		return err
	}

	return g.imports.write(g.output)
}

// writeTypeChecks writes a statement to force the compiler to perform a type
// check for all Marshallable types referenced by the generated code.
func (g *Generator) writeTypeChecks(ms map[string]struct{}) error {
	if len(ms) == 0 {
		return nil
	}

	msl := make([]string, 0, len(ms))
	for m := range ms {
		msl = append(msl, m)
	}
	sort.Strings(msl)

	var buf bytes.Buffer
	fmt.Fprint(&buf, "// Marshallable types used by this file.\n")

	for _, m := range msl {
		fmt.Fprintf(&buf, "var _ marshal.Marshallable = (*%s)(nil)\n", m)
	}
	fmt.Fprint(&buf, "\n")

	_, err := fmt.Fprint(g.output, buf.String())
	return err
}

// parse processes all input files passed this generator and produces a set of
// parsed go ASTs.
func (g *Generator) parse() ([]*ast.File, []*token.FileSet, error) {
	debugf("go_marshal invoked with %d input files:\n", len(g.inputs))
	for _, path := range g.inputs {
		debugf("  %s\n", path)
	}

	files := make([]*ast.File, 0, len(g.inputs))
	fsets := make([]*token.FileSet, 0, len(g.inputs))

	for _, path := range g.inputs {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			// Not a valid input file?
			return nil, nil, fmt.Errorf("input %q can't be parsed: %w", path, err)
		}

		if debugEnabled() {
			debugf("AST for %q:\n", path)
			ast.Print(fset, f)
		}

		files = append(files, f)
		fsets = append(fsets, fset)
	}

	return files, fsets, nil
}

// sliceAPI carries information about the '+marshal slice' directive.
type sliceAPI struct {
	// Comment node in the AST containing the +marshal tag.
	comment *ast.Comment
	// Identifier fragment to use when naming generated functions for the slice
	// API.
	ident string
	// Whether the generated functions should reference the newtype name, or the
	// inner type name. Only meaningful on newtype declarations on primitives.
	inner bool
}

// marshallableType carries information about a type marked with the '+marshal'
// directive.
type marshallableType struct {
	spec    *ast.TypeSpec
	slice   *sliceAPI
	recv    string
	dynamic bool
}

func newMarshallableType(fset *token.FileSet, tagLine *ast.Comment, spec *ast.TypeSpec) *marshallableType {
	mt := &marshallableType{
		spec:  spec,
		slice: nil,
	}

	var unhandledTags []string

	for _, tag := range strings.Fields(strings.TrimPrefix(tagLine.Text, "// +marshal")) {
		if strings.HasPrefix(tag, "slice:") {
			tokens := strings.Split(tag, ":")
			if len(tokens) < 2 || len(tokens) > 3 {
				abortAt(fset.Position(tagLine.Slash), fmt.Sprintf("+marshal directive has invalid 'slice' clause. Expecting format 'slice:<IDENTIFIER>[:inner]', got '%v'", tag))
			}
			if len(tokens[1]) == 0 {
				abortAt(fset.Position(tagLine.Slash), "+marshal slice directive has empty identifier argument. Expecting '+marshal slice:identifier'")
			}

			sa := &sliceAPI{
				comment: tagLine,
				ident:   tokens[1],
			}
			mt.slice = sa

			if len(tokens) == 3 {
				if tokens[2] != "inner" {
					abortAt(fset.Position(tagLine.Slash), "+marshal slice directive has an invalid argument. Expecting '+marshal slice:<IDENTIFIER>[:inner]'")
				}
				sa.inner = true
			}

			continue
		} else if tag == "dynamic" {
			mt.dynamic = true
			continue
		}

		unhandledTags = append(unhandledTags, tag)
	}

	if len(unhandledTags) > 0 {
		abortAt(fset.Position(tagLine.Slash), fmt.Sprintf("+marshal directive contained the following unknown clauses: %v", strings.Join(unhandledTags, " ")))
	}

	return mt
}

// collectMarshallableTypes walks the parsed AST and collects a list of type
// declarations for which we need to generate the Marshallable interface.
func (g *Generator) collectMarshallableTypes(a *ast.File, f *token.FileSet) map[*ast.TypeSpec]*marshallableType {
	recv := make(map[string]string) // Type name to recevier name.
	types := make(map[*ast.TypeSpec]*marshallableType)
	for _, decl := range a.Decls {
		gdecl, ok := decl.(*ast.GenDecl)
		// Type declaration?
		if !ok || gdecl.Tok != token.TYPE {
			// Is this a function declaration? We remember receiver names.
			d, ok := decl.(*ast.FuncDecl)
			if ok && d.Recv != nil && len(d.Recv.List) == 1 {
				// Accept concrete methods & pointer methods.
				ident, ok := d.Recv.List[0].Type.(*ast.Ident)
				if !ok {
					var st *ast.StarExpr
					st, ok = d.Recv.List[0].Type.(*ast.StarExpr)
					if ok {
						ident, ok = st.X.(*ast.Ident)
					}
				}
				// The receiver name may be not present.
				if ok && len(d.Recv.List[0].Names) == 1 {
					// Recover the type receiver name in this case.
					recv[ident.Name] = d.Recv.List[0].Names[0].Name
				}
			}
			debugfAt(f.Position(decl.Pos()), "Skipping declaration since it's not a type declaration.\n")
			continue
		}
		// Does it have a comment?
		if gdecl.Doc == nil {
			debugfAt(f.Position(gdecl.Pos()), "Skipping declaration since it doesn't have a comment.\n")
			continue
		}
		// Does the comment contain a "+marshal" line?
		marked := false
		var tagLine *ast.Comment
		for _, c := range gdecl.Doc.List {
			if strings.HasPrefix(c.Text, "// +marshal") {
				marked = true
				tagLine = c
				break
			}
		}
		if !marked {
			debugfAt(f.Position(gdecl.Pos()), "Skipping declaration since it doesn't have a comment containing +marshal line.\n")
			continue
		}
		for _, spec := range gdecl.Specs {
			// We already confirmed we're in a type declaration earlier, so this
			// cast will succeed.
			t := spec.(*ast.TypeSpec)
			switch t.Type.(type) {
			case *ast.StructType:
				debugfAt(f.Position(t.Pos()), "Collected marshallable struct %s.\n", t.Name.Name)
			case *ast.Ident: // Newtype on primitive.
				debugfAt(f.Position(t.Pos()), "Collected marshallable newtype on primitive %s.\n", t.Name.Name)
			case *ast.ArrayType: // Newtype on array.
				debugfAt(f.Position(t.Pos()), "Collected marshallable newtype on array %s.\n", t.Name.Name)
			default:
				// A user specifically requested marshalling on this type, but we
				// don't support it.
				abortAt(f.Position(t.Pos()), fmt.Sprintf("Marshalling codegen was requested on type '%s', but go-marshal doesn't support this kind of declaration.\n", t.Name))
			}
			types[t] = newMarshallableType(f, tagLine, t)
		}
	}
	// Update the types with the last seen receiver. As long as the
	// receiver name is consistent for the type, then we will generate
	// code that is still consistent with itself.
	for t, mt := range types {
		r, ok := recv[t.Name.Name]
		if !ok {
			mt.recv = receiverName(t) // Default.
			continue
		}
		mt.recv = r // Last seen.
	}
	return types
}

// collectImports collects all imports from all input source files. Some of
// these imports are copied to the generated output, if they're referenced by
// the generated code.
//
// collectImports de-duplicates imports while building the list, and ensures
// identifiers in the generated code don't conflict with any imported package
// names.
func (g *Generator) collectImports(a *ast.File, f *token.FileSet) map[string]importStmt {
	is := make(map[string]importStmt)
	for _, decl := range a.Decls {
		gdecl, ok := decl.(*ast.GenDecl)
		// Import statement?
		if !ok || gdecl.Tok != token.IMPORT {
			continue
		}
		for _, spec := range gdecl.Specs {
			i := g.imports.addFromSpec(spec.(*ast.ImportSpec), f)
			debugf("Collected import '%s' as '%s'\n", i.path, i.name)

			// Make sure we have an import that doesn't use any local names that
			// would conflict with identifiers in the generated code.
			if len(i.name) == 1 && i.name != "_" {
				abortAt(f.Position(spec.Pos()), fmt.Sprintf("Import has a single character local name '%s'; this may conflict with code generated by go_marshal, use a multi-character import alias", i.name))
			}
			if _, ok := badIdentsMap[i.name]; ok {
				abortAt(f.Position(spec.Pos()), fmt.Sprintf("Import name '%s' is likely to conflict with code generated by go_marshal, use a different import alias", i.name))
			}
		}
	}
	return is

}

func (g *Generator) generateOne(t *marshallableType, fset *token.FileSet) *interfaceGenerator {
	i := newInterfaceGenerator(t.spec, t.recv, fset)
	if t.dynamic {
		if t.slice != nil {
			abortAt(fset.Position(t.slice.comment.Slash), "Slice API is not supported for dynamic types because it assumes that each slice element is statically sized.")
		}
		// No validation needed, assume the user knows what they are doing.
		i.emitMarshallableForDynamicType()
		return i
	}
	switch ty := t.spec.Type.(type) {
	case *ast.StructType:
		i.validateStruct(t.spec, ty)
		i.emitMarshallableForStruct(ty)
		if t.slice != nil {
			i.emitMarshallableSliceForStruct(ty, t.slice)
		}
	case *ast.Ident:
		i.validatePrimitiveNewtype(ty)
		i.emitMarshallableForPrimitiveNewtype(ty)
		if t.slice != nil {
			i.emitMarshallableSliceForPrimitiveNewtype(ty, t.slice)
		}
	case *ast.ArrayType:
		i.validateArrayNewtype(t.spec.Name, ty)
		// After validate, we can safely call arrayLen.
		i.emitMarshallableForArrayNewtype(t.spec.Name, ty, ty.Elt.(*ast.Ident))
		if t.slice != nil {
			abortAt(fset.Position(t.slice.comment.Slash), "Array type marked as '+marshal slice:...', but this is not supported. Perhaps fold one of the dimensions?")
		}
	default:
		// This should've been filtered out by collectMarshallabeTypes.
		panic(fmt.Sprintf("Unexpected type %+v", ty))
	}
	return i
}

// generateOneTestSuite generates a test suite for the automatically generated
// implementations type t.
func (g *Generator) generateOneTestSuite(t *marshallableType) *testGenerator {
	i := newTestGenerator(t.spec, t.recv)
	i.emitTests(t.slice)
	return i
}

// Run is the entry point to code generation using g.
//
// Run parses all input source files specified in g and emits generated code.
func (g *Generator) Run() error {
	// Parse our input source files into ASTs and token sets.
	asts, fsets, err := g.parse()
	if err != nil {
		return err
	}

	if len(asts) != len(fsets) {
		panic("ASTs and FileSets don't match")
	}

	// Map of imports in source files; key = local package name, value = import
	// path.
	is := make(map[string]importStmt)
	for i, a := range asts {
		// Collect all imports from the source files. We may need to copy some
		// of these to the generated code if they're referenced. This has to be
		// done before the loop below because we need to process all ASTs before
		// we start requesting imports to be copied one by one as we encounter
		// them in each generated source.
		for name, i := range g.collectImports(a, fsets[i]) {
			is[name] = i
		}
	}

	var impls []*interfaceGenerator
	var ts []*testGenerator
	// Set of Marshallable types referenced by generated code.
	ms := make(map[string]struct{})
	for i, a := range asts {
		// Collect type declarations marked for code generation and generate
		// Marshallable interfaces.
		var sortedTypes []*marshallableType
		for _, t := range g.collectMarshallableTypes(a, fsets[i]) {
			sortedTypes = append(sortedTypes, t)
		}
		sort.Slice(sortedTypes, func(x, y int) bool {
			// Sort by type name, which should be unique within a package.
			return sortedTypes[x].spec.Name.String() < sortedTypes[y].spec.Name.String()
		})
		for _, t := range sortedTypes {
			impl := g.generateOne(t, fsets[i])
			// Collect Marshallable types referenced by the generated code.
			for ref := range impl.ms {
				ms[ref] = struct{}{}
			}
			impls = append(impls, impl)
			// Collect imports referenced by the generated code and add them to
			// the list of imports we need to copy to the generated code.
			for name := range impl.is {
				if !g.imports.markUsed(name) {
					panic(fmt.Sprintf("Generated code for '%s' referenced a non-existent import with local name '%s'. Either go-marshal needs to add an import to the generated file, or a package in an input source file has a package name differ from the final component of its path, which go-marshal doesn't know how to detect; use an import alias to work around this limitation.", impl.typeName(), name))
				}
			}
			// Do not generate tests for dynamic types because they inherently
			// violate some go_marshal requirements.
			if !t.dynamic {
				ts = append(ts, g.generateOneTestSuite(t))
			}
		}
	}

	// Write output file header. These include things like package name and
	// import statements.
	if err := g.writeHeader(); err != nil {
		return err
	}

	// Write type checks for referenced marshallable types to output file.
	if err := g.writeTypeChecks(ms); err != nil {
		return err
	}

	// Write generated interfaces to output file.
	for _, i := range impls {
		if err := i.write(g.output); err != nil {
			return err
		}
	}

	// Write generated tests to test file.
	return g.writeTests(ts)
}

// writeTests outputs tests for the generated interface implementations to a go
// source file.
func (g *Generator) writeTests(ts []*testGenerator) error {
	var b sourceBuffer

	// Write the unconditional test file. This file is always compiled,
	// regardless of what build tags were specified on the original input
	// files. We use this file to guarantee we never end up with an empty test
	// file, as that causes the build to fail with "no tests/benchmarks/examples
	// found".
	//
	// There's no easy way to determine ahead of time if we'll end up with an
	// empty build file since build constraints can arbitrarily cause some of
	// the original types to be not defined. We also have no way to tell bazel
	// to omit the entire test suite since the output files are already defined
	// before go-marshal is called.
	b.emit("// Automatically generated marshal tests. See tools/go_marshal.\n\n")
	b.emit("package %s\n\n", g.pkg)
	b.emit("func Example() {\n")
	b.inIndent(func() {
		b.emit("// This example is intentionally empty, and ensures this package contains at\n")
		b.emit("// least one testable entity. go-marshal is forced to emit a test package if the\n")
		b.emit("// input package is marked marshallable, but emitting no testable entities \n")
		b.emit("// results in a build failure.\n")
	})
	b.emit("}\n")
	if err := b.write(g.outputTestUC); err != nil {
		return err
	}

	// Now generate the real test file that contains the real types we
	// processed. These need to be conditionally compiled according to the build
	// tags, as the original types may not be defined under all build
	// configurations.

	b.reset()
	b.emit("// Automatically generated marshal tests. See tools/go_marshal.\n\n")

	// Emit build constraints.
	bcexpr, err := constraintutil.CombineFromFiles(g.inputs)
	if err != nil {
		return err
	}
	b.emit(constraintutil.Lines(bcexpr))

	b.emit("package %s\n\n", g.pkg)
	if err := b.write(g.outputTest); err != nil {
		return err
	}

	// Collect and write test import statements.
	imports := newImportTable()
	for _, t := range ts {
		imports.merge(t.imports)
	}

	if err := imports.write(g.outputTest); err != nil {
		return err
	}

	// Write test functions.
	for _, t := range ts {
		if err := t.write(g.outputTest); err != nil {
			return err
		}
	}
	return nil
}
