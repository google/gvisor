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
	FactTypes: []analysis.Fact{
		(*UnresolvedLinknames)(nil),
		(*ResolvedSymbols)(nil),
	},
}

// symbolMap is a map of all known or unknown symbols, with their signature.
//
// It is keyed by package, then symbol, with the simplified signature as the value.
type symbolMap map[string]map[string]string

// mergeOrResolve checks all symbol signatures.
//
// If merge is true, then the resulting map will be the union of the two maps.
// If merge is false, then the resulting map will be the first with the second
// symbolMap subtracted.
func (s *symbolMap) mergeOrResolve(pass *analysis.Pass, other symbolMap, merge bool, resolvePos func(pkgName, symbolName string) token.Pos) {
	for pkgName, symbols := range other {
		localSymbols, ok := (*s)[pkgName]
		if !ok {
			if merge {
				(*s)[pkgName] = symbols
			}
			continue
		}
		var resolved []string // Used only if !merge.
		for symbolName, otherSig := range symbols {
			localSig, ok := localSymbols[symbolName]
			if !ok {
				if merge {
					localSymbols[symbolName] = otherSig
				}
				continue
			}
			if localSig != otherSig {
				switch {
				case symbolName == "ifaceE2I":
					// The runtime uses a different signature for this than other packages, e.g.
					// the runtime has func(uintptr, eface, uintptr) whereas externally it is
					// declared as func(uintptr, any, uintptr). This is a clever way to directly
					// access the interface object, but breaks this change. We ignore this.
				default:
					pass.Reportf(resolvePos(pkgName, symbolName), "symbol %q has signature %q, expected signature %q", symbolName, localSig, otherSig)
				}
			}
			if !merge {
				resolved = append(resolved, symbolName)
			}
		}
		for _, symbolName := range resolved {
			delete(localSymbols, symbolName)
		}
	}
}

// ResolvedSymbols is a fact containing known symbols and their simplified type.
type ResolvedSymbols symbolMap

// AFact implements analysis.Fact.AFact.
func (*ResolvedSymbols) AFact() {}

// merge merges all known symbols.
func (r *ResolvedSymbols) merge(pass *analysis.Pass, other ResolvedSymbols, resolvePos func(pkgName, symbolName string) token.Pos) {
	((*symbolMap)(r)).mergeOrResolve(pass, (symbolMap)(other), true /* merge */, resolvePos)
}

// UnresolvedLinknames is a fact containing symbols that have not been validated.
type UnresolvedLinknames symbolMap

// AFact implements analysis.Fact.AFact.
func (*UnresolvedLinknames) AFact() {}

// merge merges all unknown symbols.
func (u *UnresolvedLinknames) merge(pass *analysis.Pass, other UnresolvedLinknames, resolvePos func(pkgName, symbolName string) token.Pos) {
	((*symbolMap)(u)).mergeOrResolve(pass, (symbolMap)(other), true /* merge */, resolvePos)
}

// resolve resolves all known symbols.
func (u *UnresolvedLinknames) resolve(pass *analysis.Pass, other ResolvedSymbols, resolvePos func(pkgName, symbolName string) token.Pos) {
	((*symbolMap)(u)).mergeOrResolve(pass, (symbolMap)(other), false /* merge */, resolvePos)
}

// resolveRemaining resolves all remaining names.
//
// This should be called only for final linking, when we expect that all symbols
// have been included directly or indirectly.
func (u *UnresolvedLinknames) resolveRemaining(pass *analysis.Pass, resolvePos func(pkgName, symbolName string) token.Pos) {
	for pkgName, pur := range *u {
		for symbolName := range pur {
			switch {
			case pkgName == "main" && symbolName == ".inittask":
				// This seems like a special case; it is not available for analysis.
			case pkgName == "runtime" && strings.HasPrefix(symbolName, "_cgo_"):
				// Ignore all _cgo_-related symbols; see below.
			default:
				pass.Reportf(resolvePos(pkgName, symbolName), "remote symbol %q not defined in package %q", symbolName, pkgName)
			}
		}
	}
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
// In the general case, the local symbol is a function declaration, and the
// remote symbol is a real function in the standard library.

// linknameSymbol describes the symbol names in a single //go:linkname
// directive.
type linknameSymbols struct {
	pos    token.Pos
	local  string
	remote string
}

func findLinknames(pass *analysis.Pass, f *ast.File) (names []linknameSymbols) {
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

// kindStr stores strings for basic kinds.
var kindStr = map[types.BasicKind]string{
	types.Bool:          "bool",
	types.Int:           "int",
	types.Int8:          "int8",
	types.Int16:         "int16",
	types.Int32:         "int32",
	types.Int64:         "int64",
	types.Uint:          "uint",
	types.Uint8:         "uint8",
	types.Uint16:        "uint16",
	types.Uint32:        "uint32",
	types.Uint64:        "uint64",
	types.Uintptr:       "uintptr",
	types.Float32:       "float32",
	types.Float64:       "float64",
	types.Complex64:     "complex64",
	types.Complex128:    "complex128",
	types.String:        "string",
	types.UnsafePointer: "uintptr", // See simplifyType; we cheat for pointers.
}

type memoizer[T comparable] struct {
	recentKeys   [8]T
	recentValues [8]string
	nextEviction int
}

func (m *memoizer[T]) get(x T) (string, bool) {
	for i, v := range m.recentKeys {
		if v == x {
			return m.recentValues[i], true
		}
	}
	return "", false
}

func (m *memoizer[T]) add(x T, s string) {
	m.recentKeys[m.nextEviction%len(m.recentKeys)] = x
	m.recentValues[m.nextEviction%len(m.recentValues)] = s
	m.nextEviction++
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var (
	memoizedSlices     memoizer[*types.Slice]
	memoizedArrays     memoizer[*types.Array]
	memoizedMaps       memoizer[*types.Map]
	memoizedStructs    memoizer[*types.Struct]
	memoizedInterfaces memoizer[*types.Interface]
	memoizedSignatures memoizer[*types.Signature]
)

// simplifyType returns a simplified type string.
func simplifyType(t types.Type, maxDepth int) (string, int) {
	if maxDepth <= 0 {
		return fmt.Sprintf("..."), maxDepth // Don't bother.
	}
	switch x := t.Underlying().(type) {
	case *types.Pointer:
		// Allow cheating for pointers.
		return "uintptr", maxDepth
	case *types.Signature:
		// For functions, recursively simplify.
		if s, ok := memoizedSignatures.get(x); ok {
			return s, maxDepth
		}
		s, minDepth := makeSignature(x, maxDepth-1)
		if minDepth > 0 {
			memoizedSignatures.add(x, s)
		}
		return s, minDepth
	case *types.Struct:
		// Build the simplified struct definition.
		if s, ok := memoizedStructs.get(x); ok {
			return s, maxDepth
		}
		s, minDepth := makeStructSignature(x, maxDepth-1)
		if minDepth > 0 {
			memoizedStructs.add(x, s)
		}
		return s, minDepth
	case *types.Basic:
		// For any basic type (Int8, etc.), we represent as the kind.
		if s, ok := kindStr[x.Kind()]; ok {
			return s, maxDepth
		}
		return fmt.Sprintf("kind#%d", t), maxDepth
	case *types.Interface:
		// Write the interface declaration, it's usually empty.
		if s, ok := memoizedInterfaces.get(x); ok {
			return s, maxDepth
		}
		s, minDepth := makeInterfaceSignature(x, maxDepth-1)
		if minDepth > 0 {
			memoizedInterfaces.add(x, s)
		}
		return s, minDepth
	case *types.Slice:
		// List as a standard slice.
		if s, ok := memoizedSlices.get(x); ok {
			return s, maxDepth
		}
		s, minDepth := simplifyType(x.Elem(), maxDepth-1)
		s = fmt.Sprintf("[]%s", s)
		if minDepth > 0 {
			memoizedSlices.add(x, s)
		}
		return s, minDepth
	case *types.Array:
		// List as an inline array definition.
		if s, ok := memoizedArrays.get(x); ok {
			return s, maxDepth
		}
		s, minDepth := simplifyType(x.Elem(), maxDepth-1)
		s = fmt.Sprintf("[%d]%s", x.Len(), s)
		if minDepth > 0 {
			memoizedArrays.add(x, s)
		}
		return s, minDepth
	case *types.Map:
		// List as the standard map.
		if s, ok := memoizedMaps.get(x); ok {
			return s, maxDepth
		}
		keyS, minDepthKey := simplifyType(x.Key(), maxDepth-1)
		valS, minDepthVal := simplifyType(x.Elem(), maxDepth-1)
		s := fmt.Sprintf("map[%s]%s", keyS, valS)
		minDepth := min(minDepthKey, minDepthVal)
		if minDepth > 0 {
			memoizedMaps.add(x, s)
		}
		return s, minDepth
	default:
		// Anything else, use the full string.
		return t.String(), maxDepth
	}
}

// makeStructSignature makes a struct signature.
func makeStructSignature(str *types.Struct, maxDepth int) (string, int) {
	parts := make([]string, 0, str.NumFields())
	minDepth := maxDepth
	for i := 0; i < len(parts); i++ {
		s, localMinDepth := simplifyType(str.Field(i).Type(), maxDepth)
		parts = append(parts, s)
		minDepth = min(localMinDepth, minDepth)
	}
	return fmt.Sprintf("struct{%s}", strings.Join(parts, ", ")), minDepth
}

// makeInterfaceSignature makes an interface signature.
func makeInterfaceSignature(iface *types.Interface, maxDepth int) (string, int) {
	parts := make([]string, 0, iface.NumMethods())
	minDepth := maxDepth
	for i := 0; i < len(parts); i++ {
		s, localMinDepth := makeSignature(iface.Method(i).Type().(*types.Signature), maxDepth)
		parts = append(parts, s)
		minDepth = min(localMinDepth, minDepth)
	}
	return fmt.Sprintf("interface{%s}", strings.Join(parts, ",")), minDepth
}

// makeSignature builds the special signature.
//
// This function preserves sensitive to basic types, but relaxes specifics around pointers.
func makeSignature(sig *types.Signature, maxDepth int) (string, int) {
	params := make([]string, 0)
	results := make([]string, 0)
	minDepth := maxDepth
	if r := sig.Recv(); r != nil {
		s, localMinDepth := simplifyType(r.Type(), maxDepth)
		params = append(params, s)
		minDepth = min(localMinDepth, minDepth)
	}
	if p := sig.Params(); p != nil {
		for i := 0; i < p.Len(); i++ {
			s, localMinDepth := simplifyType(p.At(i).Type(), maxDepth)
			params = append(params, s)
			minDepth = min(localMinDepth, minDepth)
		}
	}
	if r := sig.Results(); r != nil {
		for i := 0; i < r.Len(); i++ {
			s, localMinDepth := simplifyType(r.At(i).Type(), maxDepth)
			results = append(results, s)
			minDepth = min(localMinDepth, minDepth)
		}
	}
	return fmt.Sprintf("func (%s) (%s)", strings.Join(params, ", "), strings.Join(results, ", ")), minDepth
}

// findAllSymbols finds all package-local symbols.
func findAllSymbols(pkg *types.Package) ResolvedSymbols {
	const initialMaxDepth = 4 // Don't allow infinite recursion.
	localSymbols := make(map[string]string)
	for _, name := range pkg.Scope().Names() {
		obj := pkg.Scope().Lookup(name)
		// Only include unexported, top-level functions. It is possible
		// to define linknames against other types, but we avoid excessive
		// excess data by not type checking these cases, which are rare.
		if _, ok := obj.(*types.Func); !ok || obj.Exported() {
			continue
		}
		localSymbols[name], _ = simplifyType(obj.Type(), initialMaxDepth)
	}
	return ResolvedSymbols{
		pkg.Path(): localSymbols,
	}
}

func run(pass *analysis.Pass) (any, error) {
	// Grab all local symbols.
	rs := findAllSymbols(pass.Pkg)

	// Check for local //go:linkname directives in this package.
	localSymbols := rs[pass.Pkg.Path()]
	localPos := make(map[string]token.Pos)
	ur := make(UnresolvedLinknames)
	for _, f := range pass.Files {
		for _, sym := range findLinknames(pass, f) {
			localSig, ok := localSymbols[sym.local]
			if !ok {
				// The localSymbols only include unexported functions. If we don't
				// match either of those, then this is a case which can be ignored.
				continue
			}

			// Note that some of these remote packages may in fact be this
			// package. We still use a single consistent pass for resolution,
			// and just use the location of the declaration if it is local.
			remotePackage, remoteName := splitSymbol(pass.Pkg, sym.remote)
			if _, ok := ur[remotePackage]; !ok {
				ur[remotePackage] = make(map[string]string)
			}
			ur[remotePackage][remoteName] = localSig
			localPos[sym.local] = sym.pos

			// Remap the local symbols, if required.
			if remotePackage == pass.Pkg.Path() {
				localPos[remoteName] = sym.pos
				localSymbols[remoteName] = localSymbols[sym.local]
				delete(localSymbols, sym.local)
			}
		}
	}

	// Build our resolution function.
	resolvePos := func(pkgName, symbolName string) token.Pos {
		if pkgName == pass.Pkg.Path() {
			return localPos[symbolName]
		}
		// Scan the top-level scope for a relevant import.
		for _, name := range pass.Pkg.Scope().Names() {
			obj := pass.Pkg.Scope().Lookup(name)
			if pn, ok := obj.(*types.PkgName); ok && pn.Pkg().Path() == pkgName {
				return pn.Pos()
			}
		}
		return 0 // No valid location.
	}

	// Merge in all underlying facts.
	for _, importPkg := range pass.Pkg.Imports() {
		var (
			iur UnresolvedLinknames
			irs ResolvedSymbols
		)
		if pass.ImportPackageFact(importPkg, &iur) {
			ur.merge(pass, iur, resolvePos)
		}
		if pass.ImportPackageFact(importPkg, &irs) {
			rs.merge(pass, irs, resolvePos)
		}
	}

	// Attempt to resolve the facts.
	ur.resolve(pass, rs, resolvePos)
	if pass.Pkg.Path() == "main" {
		ur.resolveRemaining(pass, resolvePos)
	}

	// Export all facts.
	pass.ExportPackageFact(&ur)
	pass.ExportPackageFact(&rs)

	return nil, nil
}
