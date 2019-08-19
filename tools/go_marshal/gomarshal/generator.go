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
)

const (
	marshalImport  = "gvisor.dev/gvisor/tools/go_marshal/marshal"
	usermemImport  = "gvisor.dev/gvisor/pkg/sentry/usermem"
	safecopyImport = "gvisor.dev/gvisor/pkg/sentry/platform/safecopy"
)

// List of identifiers we use in generated code, that may conflict a
// similarly-named source identifier. Avoid problems by refusing the generate
// code when we see these.
//
// This only applies to import aliases at the moment. All other identifiers
// are qualified by a receiver argument, since they're struct fields.
//
// All recievers are single letters, so we don't allow import aliases to be a
// single letter.
var badIdents = []string{
	"src", "srcs", "dst", "dsts", "blk", "buf", "err",
	// All single-letter identifiers.
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
	// Package name for the generated file.
	pkg string
	// Go import path for package we're processing. This package should directly
	// declare the type we're generating code for.
	declaration string
	// Set of extra packages to import in the generated file.
	imports *importTable
}

// NewGenerator creates a new code Generator.
func NewGenerator(srcs []string, out, outTest, pkg, declaration string, imports []string) (*Generator, error) {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("Couldn't open output file %q: %v", out, err)
	}
	fTest, err := os.OpenFile(outTest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("Couldn't open test output file %q: %v", out, err)
	}
	g := Generator{
		inputs:      srcs,
		output:      f,
		outputTest:  fTest,
		pkg:         pkg,
		declaration: declaration,
		imports:     newImportTable(),
	}
	for _, i := range imports {
		// All imports on the extra imports list are unconditionally marked as
		// used, so they're always added to the generated code.
		g.imports.add(i).markUsed()
	}
	g.imports.add(marshalImport).markUsed()
	// The follow imports may or may not be used by the generated
	// code, depending what's required for the target types. Don't
	// mark these imports as used by default.
	g.imports.add(usermemImport)
	g.imports.add(safecopyImport)
	g.imports.add("unsafe")

	return &g, nil
}

// writeHeader writes the header for the generated source file. The header
// includes the package name, package level comments and import statements.
func (g *Generator) writeHeader() error {
	var b sourceBuffer
	b.emit("// Automatically generated marshal implementation. See tools/go_marshal.\n\n")
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
	for m, _ := range ms {
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
			return nil, nil, fmt.Errorf("Input %q can't be parsed: %v", path, err)
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

// collectMarshallabeTypes walks the parsed AST and collects a list of type
// declarations for which we need to generate the Marshallable interface.
func (g *Generator) collectMarshallabeTypes(a *ast.File, f *token.FileSet) []*ast.TypeSpec {
	var types []*ast.TypeSpec
	for _, decl := range a.Decls {
		gdecl, ok := decl.(*ast.GenDecl)
		// Type declaration?
		if !ok || gdecl.Tok != token.TYPE {
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
		for _, c := range gdecl.Doc.List {
			if c.Text == "// +marshal" {
				marked = true
				break
			}
		}
		if !marked {
			debugfAt(f.Position(gdecl.Pos()), "Skipping declaration since it doesn't have a comment containing +marshal line.\n")
			continue
		}
		for _, spec := range gdecl.Specs {
			// We already confirmed we're in a type declaration earlier.
			t := spec.(*ast.TypeSpec)
			if _, ok := t.Type.(*ast.StructType); ok {
				debugfAt(f.Position(t.Pos()), "Collected marshallable type %s.\n", t.Name.Name)
				types = append(types, t)
				continue
			}
			debugf("Skipping declaration %v since it's not a struct declaration.\n", gdecl)
		}
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
	badImportNames := make(map[string]bool)
	for _, i := range badIdents {
		badImportNames[i] = true
	}

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
			if badImportNames[i.name] {
				abortAt(f.Position(spec.Pos()), fmt.Sprintf("Import name '%s' is likely to conflict with code generated by go_marshal, use a different import alias", i.name))
			}
		}
	}
	return is

}

func (g *Generator) generateOne(t *ast.TypeSpec, fset *token.FileSet) *interfaceGenerator {
	// We're guaranteed to have only struct type specs by now. See
	// Generator.collectMarshallabeTypes.
	i := newInterfaceGenerator(t, fset)
	i.validate()
	i.emitMarshallable()
	return i
}

// generateOneTestSuite generates a test suite for the automatically generated
// implementations type t.
func (g *Generator) generateOneTestSuite(t *ast.TypeSpec) *testGenerator {
	i := newTestGenerator(t, g.declaration)
	i.emitTests()
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
		for _, t := range g.collectMarshallabeTypes(a, fsets[i]) {
			impl := g.generateOne(t, fsets[i])
			// Collect Marshallable types referenced by the generated code.
			for ref, _ := range impl.ms {
				ms[ref] = struct{}{}
			}
			impls = append(impls, impl)
			// Collect imports referenced by the generated code and add them to
			// the list of imports we need to copy to the generated code.
			for name, _ := range impl.is {
				if !g.imports.markUsed(name) {
					panic(fmt.Sprintf("Generated code for '%s' referenced a non-existent import with local name '%s'", impl.typeName(), name))
				}
			}
			ts = append(ts, g.generateOneTestSuite(t))
		}
	}

	// Tool was invoked with input files with no data structures marked for code
	// generation. This is probably not what the user intended.
	if len(impls) == 0 {
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "go_marshal invoked on these files, but they don't contain any types requiring code generation. Either mark some with \"// +marshal\" or disable marshalling codegen by putting 'marshal = False' in the BUILD rule:\n")
		for _, i := range g.inputs {
			fmt.Fprintf(&buf, "  %s\n", i)
		}
		abort(buf.String())
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
	b.emit("package %s_test\n\n", g.pkg)
	if err := b.write(g.outputTest); err != nil {
		return err
	}

	imports := newImportTable()
	for _, t := range ts {
		imports.merge(t.imports)
	}

	if err := imports.write(g.outputTest); err != nil {
		return err
	}

	for _, t := range ts {
		if err := t.write(g.outputTest); err != nil {
			return err
		}
	}
	return nil
}
