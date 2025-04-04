/*
Copyright 2020 The Kubermatic Kubernetes Platform contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"math"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
)

// Filter is a CPU filter function applied to a single record.
type Filter func(record, minCPU, maxCPU int) bool

func FilterCPU(record, minCPU, maxCPU int) bool {
	// unlimited
	if maxCPU == 0 {
		maxCPU = math.MaxInt32
	}
	if record >= minCPU && record <= maxCPU {
		return true
	}
	return false
}

func FilterMemory(record, minMemory, maxMemory int) bool {
	// unlimited
	if maxMemory == 0 {
		maxMemory = math.MaxInt32
	}
	if record >= minMemory && record <= maxMemory {
		return true
	}
	return false
}

func FilterGPU(record int, enableGPU bool) bool {
	if !enableGPU && record > 0 {
		return false
	}

	return true
}

func DetermineMachineFlavorFilter(seedMachineFilter, globalMachineFilter *kubermaticv1.MachineFlavorFilter) kubermaticv1.MachineFlavorFilter {
	var filter kubermaticv1.MachineFlavorFilter
	if seedMachineFilter != nil {
		filter = *seedMachineFilter
	} else if globalMachineFilter != nil {
		filter = *globalMachineFilter
	}
	return filter
}
