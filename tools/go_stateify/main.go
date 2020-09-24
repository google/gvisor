// Copyright 2018 The gVisor Authors.
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
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"gvisor.dev/gvisor/tools/tags"
)

var (
	fullPkg  = flag.String("fullpkg", "", "fully qualified output package")
	imports  = flag.String("imports", "", "extra imports for the output file")
	output   = flag.String("output", "", "output file")
	statePkg = flag.String("statepkg", "", "state import package; defaults to empty")
)

// resolveTypeName returns a qualified type name.
func resolveTypeName(typ ast.Expr) (field string, qualified string) {
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
	field = typ.(*ast.Ident).Name
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
func scanFields(ss *ast.StructType, prefix string, fn scanFunctions) {
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
			name, _ = resolveTypeName(field.Type)
		}

		// Skip _ fields.
		if name == "_" {
			continue
		}

		// Is this a anonymous struct? If yes, then continue the
		// recursion with the given prefix. We don't pay attention to
		// any tags on the top-level struct field.
		tag := extractStateTag(field.Tag)
		if anon, ok := field.Type.(*ast.StructType); ok && tag == "" {
			scanFields(anon, name+".", fn)
			continue
		}

		switch tag {
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
	if *fullPkg == "" {
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

	// Common closures.
	emitRegister := func(name string) {
		initCalls = append(initCalls, fmt.Sprintf("%sRegister((*%s)(nil))", statePrefix, name))
	}

	// Automated warning.
	fmt.Fprint(outputFile, "// automatically generated by stateify.\n\n")

	// Emit build tags.
	if t := tags.Aggregate(flag.Args()); len(t) > 0 {
		fmt.Fprintf(outputFile, "%s\n\n", strings.Join(t.Lines(), "\n"))
	}

	// Emit the package name.
	_, pkg := filepath.Split(*fullPkg)
	fmt.Fprintf(outputFile, "package %s\n\n", pkg)

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
		typeName   string
		methodName string
	}

	// Search for and add all method to a set. We auto-detecting several
	// different methods (and insert them if we don't find them, in order
	// to ensure that expectations match reality).
	//
	// While we do this, figure out the right receiver name. If there are
	// multiple distinct receivers, then we will just pick the last one.
	simpleMethods := make(map[method]struct{})
	receiverNames := make(map[string]string)
	for _, f := range files {
		// Go over all functions.
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if d.Recv == nil || len(d.Recv.List) != 1 {
				// Not a named method.
				continue
			}

			// Save the method and the receiver.
			name, _ := resolveTypeName(d.Recv.List[0].Type)
			simpleMethods[method{
				typeName:   name,
				methodName: d.Name.Name,
			}] = struct{}{}
			if len(d.Recv.List[0].Names) > 0 {
				receiverNames[name] = d.Recv.List[0].Names[0].Name
			}
		}
	}

	for _, f := range files {
		// Go over all named types.
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.GenDecl)
			if !ok || d.Tok != token.TYPE {
				continue
			}

			// Only generate code for types marked "// +stateify
			// savable" in one of the proceeding comment lines. If
			// the line is marked "// +stateify type" then only
			// generate type information and register the type.
			if d.Doc == nil {
				continue
			}
			var (
				generateTypeInfo    = false
				generateSaverLoader = false
			)
			for _, l := range d.Doc.List {
				if l.Text == "// +stateify savable" {
					generateTypeInfo = true
					generateSaverLoader = true
					break
				}
				if l.Text == "// +stateify type" {
					generateTypeInfo = true
				}
			}
			if !generateTypeInfo && !generateSaverLoader {
				continue
			}

			for _, gs := range d.Specs {
				ts := gs.(*ast.TypeSpec)
				recv, ok := receiverNames[ts.Name.Name]
				if !ok {
					// Maybe no methods were defined?
					recv = strings.ToLower(ts.Name.Name[:1])
				}
				switch x := ts.Type.(type) {
				case *ast.StructType:
					maybeEmitImports()

					// Record the slot for each field.
					fieldCount := 0
					fields := make(map[string]int)
					emitField := func(name string) {
						fmt.Fprintf(outputFile, "		\"%s\",\n", name)
						fields[name] = fieldCount
						fieldCount++
					}
					emitFieldValue := func(name string, _ string) {
						emitField(name)
					}
					emitLoadValue := func(name, typName string) {
						fmt.Fprintf(outputFile, "	stateSourceObject.LoadValue(%d, new(%s), func(y interface{}) { %s.load%s(y.(%s)) })\n", fields[name], typName, recv, camelCased(name), typName)
					}
					emitLoad := func(name string) {
						fmt.Fprintf(outputFile, "	stateSourceObject.Load(%d, &%s.%s) // checkatomic: allowed.\n", fields[name], recv, name)
					}
					emitLoadWait := func(name string) {
						fmt.Fprintf(outputFile, "	stateSourceObject.LoadWait(%d, &%s.%s) // checkatomic: allowed.\n", fields[name], recv, name)
					}
					emitSaveValue := func(name, typName string) {
						fmt.Fprintf(outputFile, "	var %sValue %s = %s.save%s()\n", name, typName, recv, camelCased(name))
						fmt.Fprintf(outputFile, "	stateSinkObject.SaveValue(%d, %sValue) // checkatomic: allowed.\n", fields[name], name)
					}
					emitSave := func(name string) {
						fmt.Fprintf(outputFile, "	stateSinkObject.Save(%d, &%s.%s)\n", fields[name], recv, name)
					}
					emitZeroCheck := func(name string) {
						fmt.Fprintf(outputFile, "	if !%sIsZeroValue(&%s.%s) { %sFailf(\"%s is %%#v, expected zero\", &%s.%s) } // checkatomic: allowed.\n", statePrefix, recv, name, statePrefix, name, recv, name)
					}

					// Generate the type name method.
					fmt.Fprintf(outputFile, "func (%s *%s) StateTypeName() string {\n", recv, ts.Name.Name)
					fmt.Fprintf(outputFile, "	return \"%s.%s\"\n", *fullPkg, ts.Name.Name)
					fmt.Fprintf(outputFile, "}\n\n")

					// Generate the fields method.
					fmt.Fprintf(outputFile, "func (%s *%s) StateFields() []string {\n", recv, ts.Name.Name)
					fmt.Fprintf(outputFile, "	return []string{\n")
					scanFields(x, "", scanFunctions{
						normal: emitField,
						wait:   emitField,
						value:  emitFieldValue,
					})
					fmt.Fprintf(outputFile, "	}\n")
					fmt.Fprintf(outputFile, "}\n\n")

					// Define beforeSave if a definition was not found. This prevents
					// the code from compiling if a custom beforeSave was defined in a
					// file not provided to this binary and prevents inherited methods
					// from being called multiple times by overriding them.
					if _, ok := simpleMethods[method{
						typeName:   ts.Name.Name,
						methodName: "beforeSave",
					}]; !ok && generateSaverLoader {
						fmt.Fprintf(outputFile, "func (%s *%s) beforeSave() {}\n\n", recv, ts.Name.Name)
					}

					// Generate the save method.
					//
					// N.B. For historical reasons, we perform the value saves first,
					// and perform the value loads last. There should be no dependency
					// on this specific behavior, but the ability to specify slots
					// allows a manual implementation to be order-dependent.
					if generateSaverLoader {
						fmt.Fprintf(outputFile, "func (%s *%s) StateSave(stateSinkObject %sSink) {\n", recv, ts.Name.Name, statePrefix)
						fmt.Fprintf(outputFile, "	%s.beforeSave()\n", recv)
						scanFields(x, "", scanFunctions{zerovalue: emitZeroCheck})
						scanFields(x, "", scanFunctions{value: emitSaveValue})
						scanFields(x, "", scanFunctions{normal: emitSave, wait: emitSave})
						fmt.Fprintf(outputFile, "}\n\n")
					}

					// Define afterLoad if a definition was not found. We do this for
					// the same reason that we do it for beforeSave.
					_, hasAfterLoad := simpleMethods[method{
						typeName:   ts.Name.Name,
						methodName: "afterLoad",
					}]
					if !hasAfterLoad && generateSaverLoader {
						fmt.Fprintf(outputFile, "func (%s *%s) afterLoad() {}\n\n", recv, ts.Name.Name)
					}

					// Generate the load method.
					//
					// N.B. See the comment above for the save method.
					if generateSaverLoader {
						fmt.Fprintf(outputFile, "func (%s *%s) StateLoad(stateSourceObject %sSource) {\n", recv, ts.Name.Name, statePrefix)
						scanFields(x, "", scanFunctions{normal: emitLoad, wait: emitLoadWait})
						scanFields(x, "", scanFunctions{value: emitLoadValue})
						if hasAfterLoad {
							// The call to afterLoad is made conditionally, because when
							// AfterLoad is called, the object encodes a dependency on
							// referred objects (i.e. fields). This means that afterLoad
							// will not be called until the other afterLoads are called.
							fmt.Fprintf(outputFile, "	stateSourceObject.AfterLoad(%s.afterLoad)\n", recv)
						}
						fmt.Fprintf(outputFile, "}\n\n")
					}

					// Add to our registration.
					emitRegister(ts.Name.Name)

				case *ast.Ident, *ast.SelectorExpr, *ast.ArrayType:
					maybeEmitImports()

					// Generate the info methods.
					fmt.Fprintf(outputFile, "func (%s *%s) StateTypeName() string {\n", recv, ts.Name.Name)
					fmt.Fprintf(outputFile, "	return \"%s.%s\"\n", *fullPkg, ts.Name.Name)
					fmt.Fprintf(outputFile, "}\n\n")
					fmt.Fprintf(outputFile, "func (%s *%s) StateFields() []string {\n", recv, ts.Name.Name)
					fmt.Fprintf(outputFile, "	return nil\n")
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
