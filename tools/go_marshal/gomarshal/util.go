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

package gomarshal

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/token"
	"io"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
)

var debug = flag.Bool("debug", false, "enables debugging output")

// receiverName returns an appropriate receiver name given a type spec.
func receiverName(t *ast.TypeSpec) string {
	if len(t.Name.Name) < 1 {
		// Zero length type name?
		panic("unreachable")
	}
	return strings.ToLower(t.Name.Name[:1])
}

// kindString returns a user-friendly representation of an AST expr type.
func kindString(e ast.Expr) string {
	switch e.(type) {
	case *ast.Ident:
		return "scalar"
	case *ast.ArrayType:
		return "array"
	case *ast.StructType:
		return "struct"
	case *ast.StarExpr:
		return "pointer"
	case *ast.FuncType:
		return "function"
	case *ast.InterfaceType:
		return "interface"
	case *ast.MapType:
		return "map"
	case *ast.ChanType:
		return "channel"
	default:
		return reflect.TypeOf(e).String()
	}
}

func forEachStructField(st *ast.StructType, fn func(f *ast.Field)) {
	for _, field := range st.Fields.List {
		fn(field)
	}
}

// fieldDispatcher is a collection of callbacks for handling different types of
// fields in a struct declaration.
type fieldDispatcher struct {
	primitive func(n, t *ast.Ident)
	selector  func(n, tX, tSel *ast.Ident)
	array     func(n *ast.Ident, a *ast.ArrayType, t *ast.Ident)
	unhandled func(n *ast.Ident)
}

// Precondition: All dispatch callbacks that will be invoked must be
// provided.
func (fd fieldDispatcher) dispatch(f *ast.Field) {
	// Each field declaration may actually be multiple declarations of the same
	// type. For example, consider:
	//
	// type Point struct {
	//     x, y, z int
	// }
	//
	// We invoke the call-backs once per such instance.

	// Handle embedded fields. Embedded fields have no names, but can be
	// referenced by the type name.
	if len(f.Names) < 1 {
		switch v := f.Type.(type) {
		case *ast.Ident:
			fd.primitive(v, v)
		case *ast.SelectorExpr:
			fd.selector(v.Sel, v.X.(*ast.Ident), v.Sel)
		default:
			// Note: Arrays can't be embedded, which is handled here.
			panic(fmt.Sprintf("Attempted to dispatch on embedded field of unsupported kind: %#v", f.Type))
		}
		return
	}

	// Non-embedded field.
	for _, name := range f.Names {
		switch v := f.Type.(type) {
		case *ast.Ident:
			fd.primitive(name, v)
		case *ast.SelectorExpr:
			fd.selector(name, v.X.(*ast.Ident), v.Sel)
		case *ast.ArrayType:
			switch t := v.Elt.(type) {
			case *ast.Ident:
				fd.array(name, v, t)
			default:
				panic(fmt.Sprintf("Array element type is of unsupported kind. Expected *ast.Ident, got %T: %+v", t, t))
			}
		default:
			fd.unhandled(name)
		}
	}
}

// debugEnabled indicates whether debugging is enabled for gomarshal.
func debugEnabled() bool {
	return *debug
}

// abort aborts the go_marshal tool with the given error message.
func abort(msg string) {
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	fmt.Print(msg)
	os.Exit(1)
}

// abortAt aborts the go_marshal tool with the given error message, with
// a reference position to the input source.
func abortAt(p token.Position, msg string) {
	abort(fmt.Sprintf("%v:\n  %s\n", p, msg))
}

// debugf conditionally prints a debug message.
func debugf(f string, a ...interface{}) {
	if debugEnabled() {
		fmt.Printf(f, a...)
	}
}

// debugfAt conditionally prints a debug message with a reference to a position
// in the input source.
func debugfAt(p token.Position, f string, a ...interface{}) {
	if debugEnabled() {
		fmt.Printf("%s:\n  %s", p, fmt.Sprintf(f, a...))
	}
}

// emit generates a line of code in the output file.
//
// emit is a wrapper around writing a formatted string to the output
// buffer. emit can be invoked in one of two ways:
//
// (1) emit("some string")
//     When emit is called with a single string argument, it is simply copied to
//     the output buffer without any further formatting.
// (2) emit(fmtString, args...)
//     emit can also be invoked in a similar fashion to *Printf() functions,
//     where the first argument is a format string.
//
// Calling emit with a single argument that is not a string will result in a
// panic, as the caller's intent is ambiguous.
func emit(out io.Writer, indent int, a ...interface{}) {
	const spacesPerIndentLevel = 4

	if len(a) < 1 {
		panic("emit() called with no arguments")
	}

	if indent > 0 {
		if _, err := fmt.Fprint(out, strings.Repeat(" ", indent*spacesPerIndentLevel)); err != nil {
			// Writing to the emit output should not fail. Typically the output
			// is a byte.Buffer; writes to these never fail.
			panic(err)
		}
	}

	first, ok := a[0].(string)
	if !ok {
		// First argument must be either the string to emit (case 1 from
		// function-level comment), or a format string (case 2).
		panic(fmt.Sprintf("First argument to emit() is not a string: %+v", a[0]))
	}

	if len(a) == 1 {
		// Single string argument. Assume no formatting requested.
		if _, err := fmt.Fprint(out, first); err != nil {
			// Writing to out should not fail.
			panic(err)
		}
		return

	}

	// Formatting requested.
	if _, err := fmt.Fprintf(out, first, a[1:]...); err != nil {
		// Writing to out should not fail.
		panic(err)
	}
}

// sourceBuffer represents fragments of generated go source code.
//
// sourceBuffer provides a convenient way to build up go souce fragments in
// memory. May be safely zero-value initialized. Not thread-safe.
type sourceBuffer struct {
	// Current indentation level.
	indent int

	// Memory buffer containing contents while they're being generated.
	b bytes.Buffer
}

func (b *sourceBuffer) reset() {
	b.indent = 0
	b.b.Reset()
}

func (b *sourceBuffer) incIndent() {
	b.indent++
}

func (b *sourceBuffer) decIndent() {
	if b.indent <= 0 {
		panic("decIndent() without matching incIndent()")
	}
	b.indent--
}

func (b *sourceBuffer) emit(a ...interface{}) {
	emit(&b.b, b.indent, a...)
}

func (b *sourceBuffer) emitNoIndent(a ...interface{}) {
	emit(&b.b, 0 /*indent*/, a...)
}

func (b *sourceBuffer) inIndent(body func()) {
	b.incIndent()
	body()
	b.decIndent()
}

func (b *sourceBuffer) write(out io.Writer) error {
	_, err := fmt.Fprint(out, b.b.String())
	return err
}

// Write implements io.Writer.Write.
func (b *sourceBuffer) Write(buf []byte) (int, error) {
	return (b.b.Write(buf))
}

// importStmt represents a single import statement.
type importStmt struct {
	// Local name of the imported package.
	name string
	// Import path.
	path string
	// Indicates whether the local name is an alias, or simply the final
	// component of the path.
	aliased bool
	// Indicates whether this import was referenced by generated code.
	used bool
	// AST node and file set representing the import statement, if any. These
	// are only non-nil if the import statement originates from an input source
	// file.
	spec *ast.ImportSpec
	fset *token.FileSet
}

func newImport(p string) *importStmt {
	name := path.Base(p)
	return &importStmt{
		name:    name,
		path:    p,
		aliased: false,
	}
}

func newImportFromSpec(spec *ast.ImportSpec, f *token.FileSet) *importStmt {
	p := spec.Path.Value[1 : len(spec.Path.Value)-1] // Strip the " quotes around path.
	name := path.Base(p)
	if name == "" || name == "/" || name == "." {
		panic(fmt.Sprintf("Couldn't process local package name for import at %s, (processed as %s)",
			f.Position(spec.Path.Pos()), name))
	}
	if spec.Name != nil {
		name = spec.Name.Name
	}
	return &importStmt{
		name:    name,
		path:    p,
		aliased: spec.Name != nil,
		spec:    spec,
		fset:    f,
	}
}

// String implements fmt.Stringer.String. This generates a string for the import
// statement appropriate for writing directly to generated code.
func (i *importStmt) String() string {
	if i.aliased {
		return fmt.Sprintf("%s %q", i.name, i.path)
	}
	return fmt.Sprintf("%q", i.path)
}

// debugString returns a debug string representing an import statement. This
// representation is not valid golang code and is used for debugging output.
func (i *importStmt) debugString() string {
	if i.spec != nil && i.fset != nil {
		return fmt.Sprintf("%s: %s", i.fset.Position(i.spec.Path.Pos()), i)
	}
	return fmt.Sprintf("(go-marshal import): %s", i)
}

func (i *importStmt) markUsed() {
	i.used = true
}

func (i *importStmt) equivalent(other *importStmt) bool {
	return i.name == other.name && i.path == other.path && i.aliased == other.aliased
}

// importTable represents a collection of importStmts.
//
// An importTable may contain multiple import statements referencing the same
// local name. All import statements aliasing to the same local name are
// technically ambiguous, as if such an import name is used in the generated
// code, it's not clear which import statement it refers to. We ignore any
// potential collisions until actually writing the import table to the generated
// source file. See importTable.write.
//
// Given the following import statements across all the files comprising a
// package marshalled:
//
// "sync"
// "pkg/sync"
// "pkg/sentry/kernel"
// ktime "pkg/sentry/kernel/time"
//
// An importTable representing them would look like this:
//
// importTable {
//     is: map[string][]*importStmt {
//         "sync": []*importStmt{
//             importStmt{name:"sync", path:"sync", aliased:false}
//             importStmt{name:"sync", path:"pkg/sync", aliased:false}
//         },
//         "kernel": []*importStmt{importStmt{
//            name: "kernel",
//            path: "pkg/sentry/kernel",
//            aliased: false
//         }},
//         "ktime": []*importStmt{importStmt{
//             name: "ktime",
//             path: "pkg/sentry/kernel/time",
//             aliased: true,
//         }},
//     }
// }
//
// Note that the local name "sync" is assigned to two different import
// statements. This is possible if the import statements are from different
// source files in the same package.
//
// Since go-marshal generates a single output file per package regardless of the
// number of input files, if "sync" is referenced by any generated code, it's
// unclear which import statement "sync" refers to. While it's theoretically
// possible to resolve this by assigning a unique local alias to each instance
// of the sync package, go-marshal currently aborts when it encounters such an
// ambiguity.
//
// TODO(b/151478251): importTable considers the final component of an import
// path to be the package name, but this is only a convention. The actual
// package name is determined by the package statement in the source files for
// the package.
type importTable struct {
	// Map of imports and whether they should be copied to the output.
	is map[string][]*importStmt
}

func newImportTable() *importTable {
	return &importTable{
		is: make(map[string][]*importStmt),
	}
}

// Merges import statements from other into i.
func (i *importTable) merge(other *importTable) {
	for name, ims := range other.is {
		i.is[name] = append(i.is[name], ims...)
	}
}

func (i *importTable) addStmt(s *importStmt) *importStmt {
	i.is[s.name] = append(i.is[s.name], s)
	return s
}

func (i *importTable) add(s string) *importStmt {
	n := newImport(s)
	return i.addStmt(n)
}

func (i *importTable) addFromSpec(spec *ast.ImportSpec, f *token.FileSet) *importStmt {
	return i.addStmt(newImportFromSpec(spec, f))
}

// Marks the import named n as used. If no such import is in the table, returns
// false.
func (i *importTable) markUsed(n string) bool {
	if ns, ok := i.is[n]; ok {
		for _, n := range ns {
			n.markUsed()
		}
		return true
	}
	return false
}

func (i *importTable) clear() {
	for _, is := range i.is {
		for _, i := range is {
			i.used = false
		}
	}
}

func (i *importTable) write(out io.Writer) error {
	if len(i.is) == 0 {
		// Nothing to import, we're done.
		return nil
	}

	imports := make([]string, 0, len(i.is))
	for name, is := range i.is {
		var lastUsed *importStmt
		var ambiguous bool

		for _, i := range is {
			if i.used {
				if lastUsed != nil {
					if !i.equivalent(lastUsed) {
						ambiguous = true
					}
				}
				lastUsed = i
			}
		}

		if ambiguous {
			// We have two or more import statements across the different source
			// files that share a local name, and at least one of these imports
			// are used by the generated code. This ambiguity can't be resolved
			// by go-marshal and requires the user intervention. Dump a list of
			// the colliding import statements and let the user modify the input
			// files as appropriate.
			var b strings.Builder
			fmt.Fprintf(&b, "The imported name %q is used by one of the types marked for marshalling, and which import statement the code refers to is ambiguous. Perhaps give the imports unique local names?\n\n", name)
			fmt.Fprintf(&b, "The following %d import statements are ambiguous for the local name %q:\n", len(is), name)
			// Note: len(is) is guaranteed to be 1 or greater or ambiguous can't
			// be true. Therefore the slicing below is safe.
			for _, i := range is[:len(is)-1] {
				fmt.Fprintf(&b, "  %v\n", i.debugString())
			}
			fmt.Fprintf(&b, "  %v", is[len(is)-1].debugString())
			panic(b.String())
		}

		if lastUsed != nil {
			imports = append(imports, lastUsed.String())
		}
	}
	sort.Strings(imports)

	var b sourceBuffer
	b.emit("import (\n")
	b.incIndent()
	for _, i := range imports {
		b.emit("%s\n", i)
	}
	b.decIndent()
	b.emit(")\n\n")

	return b.write(out)
}
