// Copyright 2023 The gVisor Authors.
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

package nvproxy

import (
	goContext "context"
	"fmt"
)

// beforeSave is invoked by stateify.
func (nvp *nvproxy) beforeSave() {
	nvp.beforeSaveImpl()
}

// afterLoad is invoked by stateify.
func (nvp *nvproxy) afterLoad(ctx goContext.Context) {
	Init()
	abiCons, ok := abis[nvp.version]
	if !ok {
		panic(fmt.Sprintf("driver version %q not found in abis map", nvp.version))
	}
	nvp.abi = abiCons.cons()
	nvp.objsFreeSet = make(map[*object]struct{})
	nvp.afterLoadImpl(ctx)
}

// beforeSave is invoked by stateify.
func (fd *frontendFD) beforeSave() {
	fd.beforeSaveImpl()
}

// afterLoad is invoked by stateify.
func (fd *frontendFD) afterLoad(ctx goContext.Context) {
	fd.afterLoadImpl(ctx)
}

// beforeSave is invoked by stateify.
func (fd *uvmFD) beforeSave() {
	fd.beforeSaveImpl()
}

// afterLoad is invoked by stateify.
func (fd *uvmFD) afterLoad(ctx goContext.Context) {
	fd.afterLoadImpl(ctx)
}
