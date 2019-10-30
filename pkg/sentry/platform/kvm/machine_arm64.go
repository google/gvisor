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

package kvm

// Get all read-only physicalRegions.
func rdonlyRegionsForSetMem() (phyRegions []physicalRegion) {
	var rdonlyRegions []region

	applyVirtualRegions(func(vr virtualRegion) {
		if excludeVirtualRegion(vr) {
			return
		}

		if !vr.accessType.Write && vr.accessType.Read {
			rdonlyRegions = append(rdonlyRegions, vr.region)
		}
	})

	for _, r := range rdonlyRegions {
		physical, _, ok := translateToPhysical(r.virtual)
		if !ok {
			continue
		}

		phyRegions = append(phyRegions, physicalRegion{
			region: region{
				virtual: r.virtual,
				length:  r.length,
			},
			physical: physical,
		})
	}

	return phyRegions
}

// Get all available physicalRegions.
func availableRegionsForSetMem() (phyRegions []physicalRegion) {
	var excludeRegions []region
	applyVirtualRegions(func(vr virtualRegion) {
		if !vr.accessType.Write {
			excludeRegions = append(excludeRegions, vr.region)
		}
	})

	phyRegions = computePhysicalRegions(excludeRegions)

	return phyRegions
}
