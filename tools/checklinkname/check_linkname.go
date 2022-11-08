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

// Package checklinkname ensures that linkname declarations match their source.
package checklinkname

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Analyzer implements the checklinkname analyzer.
var Analyzer = &analysis.Analyzer{
	Name: "checklinkname",
	Doc:  "verifies that linkname declarations match their source",
	Run:  run,
}

// go:linkname can be rather confusing. https://pkg.go.dev/cmd/compile says:
//
// //go:linkname localname [importpath.name]
//
// This special directive does not apply to the Go code that follows it.
// Instead, the //go:linkname directive instructs the compiler to use
// “importpath.name” as the object file symbol name for the variable or
// function declared as “localname” in the source code. If the
// “importpath.name” argument is omitted, the directive uses the symbol's
// default object file symbol name and only has the effect of making the symbol
// accessible to other packages. Because this directive can subvert the type
// system and package modularity, it is only enabled in files that have
// imported "unsafe".
//
// In this package we use the term "local" to refer to the symbol name in the
// same package as the //go:linkname directive, whose name will be changed by
// the linker. We use the term "remote" to refer to the symbol name that we are
// changing to.
//
// In the general case, the local symbol is a function declaration, and the
// remote symbol is a real function in the standard library.

// linknameSignatures describes a the type signatures of the symbols in a
// //go:linkname directive.
type linknameSignatures struct {
	local  string
	remote string // equivalent to local if "".
}

func (l *linknameSignatures) Remote() string {
	if l.remote == "" {
		return l.local
	}
	return l.remote
}

// linknameSymbols describes the symbol namess in a single //go:linkname
// directive.
type linknameSymbols struct {
	pos    token.Pos
	local  string
	remote string
}

func findLinknames(pass *analysis.Pass, f *ast.File) []linknameSymbols {
	var names []linknameSymbols

	for _, cg := range f.Comments {
		for _, c := range cg.List {
			if len(c.Text) <= 2 || !strings.HasPrefix(c.Text[2:], "go:linkname ") {
				continue
			}

			f := strings.Fields(c.Text)
			if len(f) < 2 || len(f) > 3 {
				// Malformed linkname. This is the same error the compiler emits.
				pass.Reportf(c.Slash, "usage: //go:linkname localname [linkname]")
			}

			if len(f) == 2 {
				// "If the “importpath.name” argument is
				// omitted, the directive uses the symbol's
				// default object file symbol name and only has
				// the effect of making the symbol accessible
				// to other packages."
				// -https://golang.org/cmd/compile
				//
				// There is no type-checking to be done here.
				continue
			}

			names = append(names, linknameSymbols{
				pos:    c.Slash,
				local:  f[1],
				remote: f[2],
			})
		}
	}

	return names
}

func splitSymbol(pkg *types.Package, symbol string) (packagePath, name string) {
	// Note that some runtime symbols can have multiple dots. e.g.,
	// runtime..init_task.
	s := strings.SplitN(symbol, ".", 2)

	switch len(s) {
	case 1:
		// Package name omitted, use current package.
		return pkg.Path(), symbol
	case 2:
		return s[0], s[1]
	default:
		panic("unreachable")
	}
}

func findObject(pkg *types.Package, symbol string) (types.Object, error) {
	packagePath, symbolName := splitSymbol(pkg, symbol)
	return findPackageObject(pkg, packagePath, symbolName)
}

func findPackageObject(pkg *types.Package, packagePath, symbolName string) (types.Object, error) {
	if pkg.Path() == packagePath {
		o := pkg.Scope().Lookup(symbolName)
		if o == nil {
			return nil, fmt.Errorf("%q not found in %q (names: %+v)", symbolName, packagePath, pkg.Scope().Names())
		}
		return o, nil
	}

	for _, p := range pkg.Imports() {
		if o, err := findPackageObject(p, packagePath, symbolName); err == nil {
			return o, nil
		}
	}

	return nil, fmt.Errorf("package %q not found", packagePath)
}

// checkOneLinkname verifies that the type of sym.local matches the type from
// knownLinknames.
func checkOneLinkname(pass *analysis.Pass, f *ast.File, sym linknameSymbols) {
	remotePackage, remoteName := splitSymbol(pass.Pkg, sym.remote)

	m, ok := knownLinknames[remotePackage]
	if !ok {
		pass.Reportf(sym.pos, "linkname to unknown symbol %q; add this symbol to checklinkname.knownLinknames type-check against the remote type", sym.remote)
		return
	}

	linkname, ok := m[remoteName]
	if !ok {
		pass.Reportf(sym.pos, "linkname to unknown symbol %q; add this symbol to checklinkname.knownLinknames type-check against the remote type", sym.remote)
		return
	}

	local, err := findObject(pass.Pkg, sym.local)
	if err != nil {
		pass.Reportf(sym.pos, "Unable to find symbol %q: %v", sym.local, err)
		return
	}

	localSig, ok := local.Type().(*types.Signature)
	if !ok {
		pass.Reportf(local.Pos(), "%q object is not a signature: %+#v", sym.local, local)
		return
	}

	if linkname.local != localSig.String() {
		pass.Reportf(local.Pos(), "%q signature got %q want %q; mismatched types?", sym.local, localSig.String(), linkname.local)
		return
	}
}

// checkOneRemote verifies that the type of sym matches wantSig.
func checkOneRemote(pass *analysis.Pass, sym, wantSig string) {
	o := pass.Pkg.Scope().Lookup(sym)
	if o == nil {
		pass.Reportf(pass.Files[0].Package, "Cannot find known symbol %q", sym)
		return
	}

	sig, ok := o.Type().(*types.Signature)
	if !ok {
		pass.Reportf(o.Pos(), "%q object is not a signature: %+#v", sym, o)
		return
	}

	if sig.String() != wantSig {
		pass.Reportf(o.Pos(), "%q signature got %q want %q; stdlib type changed?", sym, sig.String(), wantSig)
		return
	}
}

func run(pass *analysis.Pass) (any, error) {
	// First, check if any remote symbols are in this package.
	p, ok := knownLinknames[pass.Pkg.Path()]
	if ok {
		for sym, l := range p {
			checkOneRemote(pass, sym, l.Remote())
		}
	}

	// Then check for local //go:linkname directives in this package.
	for _, f := range pass.Files {
		names := findLinknames(pass, f)
		for _, n := range names {
			checkOneLinkname(pass, f, n)
		}
	}

	return nil, nil
}
