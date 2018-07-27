// Copyright 2018 Google Inc.
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

// Stateify provides a simple way to generate Load/Save methods based on
// existing types and struct tags.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"sync"
)

var (
	pkg      = flag.String("pkg", "", "output package")
	imports  = flag.String("imports", "", "extra imports for the output file")
	output   = flag.String("output", "", "output file")
	statePkg = flag.String("statepkg", "", "state import package; defaults to empty")
	explicit = flag.Bool("explicit", false, "only generate for types explicitly tagged '// +stateify savable'")
)

// resolveTypeName returns a qualified type name.
func resolveTypeName(name string, typ ast.Expr) (field string, qualified string) {
	for done := false; !done; {
		// Resolve star expressions.
		switch rs := typ.(type) {
		case *ast.StarExpr:
			qualified += "*"
			typ = rs.X
		case *ast.ArrayType:
			if rs.Len == nil {
				// Slice type declaration.
				qualified += "[]"
			} else {
				// Array type declaration.
				qualified += "[" + rs.Len.(*ast.BasicLit).Value + "]"
			}
			typ = rs.Elt
		default:
			// No more descent.
			done = true
		}
	}

	// Resolve a package selector.
	sel, ok := typ.(*ast.SelectorExpr)
	if ok {
		qualified = qualified + sel.X.(*ast.Ident).Name + "."
		typ = sel.Sel
	}

	// Figure out actual type name.
	ident, ok := typ.(*ast.Ident)
	if !ok {
		panic(fmt.Sprintf("type not supported: %s (involves anonymous types?)", name))
	}
	field = ident.Name
	qualified = qualified + field
	return
}

// extractStateTag pulls the relevant state tag.
func extractStateTag(tag *ast.BasicLit) string {
	if tag == nil {
		return ""
	}
	if len(tag.Value) < 2 {
		return ""
	}
	return reflect.StructTag(tag.Value[1 : len(tag.Value)-1]).Get("state")
}

// scanFunctions is a set of functions passed to scanFields.
type scanFunctions struct {
	zerovalue func(name string)
	normal    func(name string)
	wait      func(name string)
	value     func(name, typName string)
}

// scanFields scans the fields of a struct.
//
// Each provided function will be applied to appropriately tagged fields, or
// skipped if nil.
//
// Fields tagged nosave are skipped.
func scanFields(ss *ast.StructType, fn scanFunctions) {
	if ss.Fields.List == nil {
		// No fields.
		return
	}

	// Scan all fields.
	for _, field := range ss.Fields.List {
		// Calculate the name.
		name := ""
		if field.Names != nil {
			// It's a named field; override.
			name = field.Names[0].Name
		} else {
			// Anonymous types can't be embedded, so we don't need
			// to worry about providing a useful name here.
			name, _ = resolveTypeName("", field.Type)
		}

		// Skip _ fields.
		if name == "_" {
			continue
		}

		switch tag := extractStateTag(field.Tag); tag {
		case "zerovalue":
			if fn.zerovalue != nil {
				fn.zerovalue(name)
			}

		case "":
			if fn.normal != nil {
				fn.normal(name)
			}

		case "wait":
			if fn.wait != nil {
				fn.wait(name)
			}

		case "manual", "nosave", "ignore":
			// Do nothing.

		default:
			if strings.HasPrefix(tag, ".(") && strings.HasSuffix(tag, ")") {
				if fn.value != nil {
					fn.value(name, tag[2:len(tag)-1])
				}
			}
		}
	}
}

func camelCased(name string) string {
	return strings.ToUpper(name[:1]) + name[1:]
}

func main() {
	// Parse flags.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if *pkg == "" {
		fmt.Fprintf(os.Stderr, "Error: package required.")
		os.Exit(1)
	}

	// Open the output file.
	var (
		outputFile *os.File
		err        error
	)
	if *output == "" || *output == "-" {
		outputFile = os.Stdout
	} else {
		outputFile, err = os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output %q: %v", *output, err)
		}
		defer outputFile.Close()
	}

	// Set the statePrefix for below, depending on the import.
	statePrefix := ""
	if *statePkg != "" {
		parts := strings.Split(*statePkg, "/")
		statePrefix = parts[len(parts)-1] + "."
	}

	// initCalls is dumped at the end.
	var initCalls []string

	// Declare our emission closures.
	emitRegister := func(name string) {
		initCalls = append(initCalls, fmt.Sprintf("%sRegister(\"%s.%s\", (*%s)(nil), state.Fns{Save: (*%s).save, Load: (*%s).load})", statePrefix, *pkg, name, name, name, name))
	}
	emitZeroCheck := func(name string) {
		fmt.Fprintf(outputFile, "	if !%sIsZeroValue(x.%s) { m.Failf(\"%s is %%v, expected zero\", x.%s) }\n", statePrefix, name, name, name)
	}
	emitLoadValue := func(name, typName string) {
		fmt.Fprintf(outputFile, "	m.LoadValue(\"%s\", new(%s), func(y interface{}) { x.load%s(y.(%s)) })\n", name, typName, camelCased(name), typName)
	}
	emitLoad := func(name string) {
		fmt.Fprintf(outputFile, "	m.Load(\"%s\", &x.%s)\n", name, name)
	}
	emitLoadWait := func(name string) {
		fmt.Fprintf(outputFile, "	m.LoadWait(\"%s\", &x.%s)\n", name, name)
	}
	emitSaveValue := func(name, typName string) {
		fmt.Fprintf(outputFile, "	var %s %s = x.save%s()\n", name, typName, camelCased(name))
		fmt.Fprintf(outputFile, "	m.SaveValue(\"%s\", %s)\n", name, name)
	}
	emitSave := func(name string) {
		fmt.Fprintf(outputFile, "	m.Save(\"%s\", &x.%s)\n", name, name)
	}

	// Emit the package name.
	fmt.Fprint(outputFile, "// automatically generated by stateify.\n\n")
	fmt.Fprintf(outputFile, "package %s\n\n", *pkg)

	// Emit the imports lazily.
	var once sync.Once
	maybeEmitImports := func() {
		once.Do(func() {
			// Emit the imports.
			fmt.Fprint(outputFile, "import (\n")
			if *statePkg != "" {
				fmt.Fprintf(outputFile, "	\"%s\"\n", *statePkg)
			}
			if *imports != "" {
				for _, i := range strings.Split(*imports, ",") {
					fmt.Fprintf(outputFile, "	\"%s\"\n", i)
				}
			}
			fmt.Fprint(outputFile, ")\n\n")
		})
	}

	files := make([]*ast.File, 0, len(flag.Args()))

	// Parse the input files.
	for _, filename := range flag.Args() {
		// Parse the file.
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
		if err != nil {
			// Not a valid input file?
			fmt.Fprintf(os.Stderr, "Input %q can't be parsed: %v\n", filename, err)
			os.Exit(1)
		}
		files = append(files, f)
	}

	type method struct {
		receiver string
		name     string
	}

	// Search for and add all methods with a pointer receiver and no other
	// arguments to a set. We support auto-detecting the existence of
	// several different methods with this signature.
	simpleMethods := map[method]struct{}{}
	for _, f := range files {

		// Go over all functions.
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if d.Name == nil || d.Recv == nil || d.Type == nil {
				// Not a named method.
				continue
			}
			if len(d.Recv.List) != 1 {
				// Wrong number of receivers?
				continue
			}
			if d.Type.Params != nil && len(d.Type.Params.List) != 0 {
				// Has argument(s).
				continue
			}
			if d.Type.Results != nil && len(d.Type.Results.List) != 0 {
				// Has return(s).
				continue
			}

			pt, ok := d.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				// Not a pointer receiver.
				continue
			}

			t, ok := pt.X.(*ast.Ident)
			if !ok {
				// This shouldn't happen with valid Go.
				continue
			}

			simpleMethods[method{t.Name, d.Name.Name}] = struct{}{}
		}
	}

	for _, f := range files {
		// Go over all named types.
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.TYPE {
				continue
			}

			if *explicit {
				// In explicit mode, only generate code for
				// types explicitly marked
				// "// +stateify savable" in one of the
				// proceeding comment lines.
				if d.Doc == nil {
					continue
				}
				savable := false
				for _, l := range d.Doc.List {
					if l.Text == "// +stateify savable" {
						savable = true
						break
					}
				}
				if !savable {
					continue
				}
			}

			for _, gs := range d.Specs {
				ts := gs.(*ast.TypeSpec)
				switch ts.Type.(type) {
				case *ast.InterfaceType, *ast.ChanType, *ast.FuncType, *ast.ParenExpr, *ast.StarExpr:
					// Don't register.
					break
				case *ast.StructType:
					maybeEmitImports()

					ss := ts.Type.(*ast.StructType)

					// Define beforeSave if a definition was not found. This
					// prevents the code from compiling if a custom beforeSave
					// was defined in a file not provided to this binary and
					// prevents inherited methods from being called multiple times
					// by overriding them.
					if _, ok := simpleMethods[method{ts.Name.Name, "beforeSave"}]; !ok {
						fmt.Fprintf(outputFile, "func (x *%s) beforeSave() {}\n", ts.Name.Name)
					}

					// Generate the save method.
					fmt.Fprintf(outputFile, "func (x *%s) save(m %sMap) {\n", ts.Name.Name, statePrefix)
					fmt.Fprintf(outputFile, "	x.beforeSave()\n")
					scanFields(ss, scanFunctions{zerovalue: emitZeroCheck})
					scanFields(ss, scanFunctions{value: emitSaveValue})
					scanFields(ss, scanFunctions{normal: emitSave, wait: emitSave})
					fmt.Fprintf(outputFile, "}\n\n")

					// Define afterLoad if a definition was not found. We do this
					// for the same reason that we do it for beforeSave.
					_, hasAfterLoad := simpleMethods[method{ts.Name.Name, "afterLoad"}]
					if !hasAfterLoad {
						fmt.Fprintf(outputFile, "func (x *%s) afterLoad() {}\n", ts.Name.Name)
					}

					// Generate the load method.
					//
					// Note that the manual loads always follow the
					// automated loads.
					fmt.Fprintf(outputFile, "func (x *%s) load(m %sMap) {\n", ts.Name.Name, statePrefix)
					scanFields(ss, scanFunctions{normal: emitLoad, wait: emitLoadWait})
					scanFields(ss, scanFunctions{value: emitLoadValue})
					if hasAfterLoad {
						// The call to afterLoad is made conditionally, because when
						// AfterLoad is called, the object encodes a dependency on
						// referred objects (i.e. fields). This means that afterLoad
						// will not be called until the other afterLoads are called.
						fmt.Fprintf(outputFile, "	m.AfterLoad(x.afterLoad)\n")
					}
					fmt.Fprintf(outputFile, "}\n\n")

					// Add to our registration.
					emitRegister(ts.Name.Name)
				case *ast.Ident, *ast.SelectorExpr, *ast.ArrayType:
					maybeEmitImports()

					_, val := resolveTypeName(ts.Name.Name, ts.Type)

					// Dispatch directly.
					fmt.Fprintf(outputFile, "func (x *%s) save(m %sMap) {\n", ts.Name.Name, statePrefix)
					fmt.Fprintf(outputFile, "	m.SaveValue(\"\", (%s)(*x))\n", val)
					fmt.Fprintf(outputFile, "}\n\n")
					fmt.Fprintf(outputFile, "func (x *%s) load(m %sMap) {\n", ts.Name.Name, statePrefix)
					fmt.Fprintf(outputFile, "	m.LoadValue(\"\", new(%s), func(y interface{}) { *x = (%s)(y.(%s)) })\n", val, ts.Name.Name, val)
					fmt.Fprintf(outputFile, "}\n\n")

					// See above.
					emitRegister(ts.Name.Name)
				}
			}
		}
	}

	if len(initCalls) > 0 {
		// Emit the init() function.
		fmt.Fprintf(outputFile, "func init() {\n")
		for _, ic := range initCalls {
			fmt.Fprintf(outputFile, "	%s\n", ic)
		}
		fmt.Fprintf(outputFile, "}\n")
	}
}
