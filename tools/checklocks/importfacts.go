// Copyright 2026 The gVisor Authors.
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

package checklocks

import "go/types"

// originObject returns obj's origin (for instantiated generic objects) when
// available, otherwise it returns obj unchanged.
func originObject(obj types.Object) types.Object {
	switch obj := obj.(type) {
	case *types.Var:
		return obj.Origin()
	case *types.Func:
		return obj.Origin()
	default:
		return obj
	}
}

// importLockGuardFacts imports lock guard facts for obj.
//
// For generic code, the `types.Object` identity observed during SSA analysis can
// differ from the declaration object where facts were exported. When that
// happens, we fall back to importing facts from the origin object.
func (pc *passContext) importLockGuardFacts(obj types.Object, lgf *lockGuardFacts) {
	pc.pass.ImportObjectFact(obj, lgf)
	if len(lgf.GuardedBy) != 0 || lgf.AtomicDisposition != atomicDisallow {
		return
	}

	// Fallback: import from the object's origin.
	if orig := originObject(obj); orig != nil && orig != obj {
		pc.pass.ImportObjectFact(orig, lgf)
	}
}

// importLockFunctionFacts imports lock function facts for fn, falling back to
// the origin object when fn is an instantiated generic function/method.
func (pc *passContext) importLockFunctionFacts(fn *types.Func, lff *lockFunctionFacts) {
	pc.pass.ImportObjectFact(fn, lff)
	if lff.Ignore || len(lff.HeldOnEntry) != 0 || len(lff.HeldOnExit) != 0 || len(lff.ExcludedOnEntry) != 0 {
		return
	}
	if orig := fn.Origin(); orig != nil && orig != fn {
		pc.pass.ImportObjectFact(orig, lff)
	}
}
