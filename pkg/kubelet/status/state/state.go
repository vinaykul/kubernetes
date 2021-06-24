/*
Copyright 2021 The Kubernetes Authors.

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

package state

import (
	"k8s.io/api/core/v1"
)

// PodResourceAllocation type is used in tracking resources allocated to pod's containers
type PodResourceAllocation map[string]map[string]v1.ResourceList

// PodResizeState type is used in tracking the last resize decision for pod
type PodResizeState map[string]v1.ResourcesResizeStatus

// Clone returns a copy of PodResourceAllocation
func (pr PodResourceAllocation) Clone() PodResourceAllocation {
	ret := make(PodResourceAllocation)
	for pod := range pr {
		ret[pod] = make(map[string]v1.ResourceList)
		for container, alloc := range pr[pod] {
			ret[pod][container] = alloc
		}
	}
	return ret
}

// Reader interface used to read current pod resource allocation state
type Reader interface {
	GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool)
	GetPodResourceAllocation() PodResourceAllocation
	GetPodResizeState(podUID string) (v1.ResourcesResizeStatus, bool)
	GetResizeState() PodResizeState
}

type writer interface {
	SetContainerResourceAllocation(podUID string, containerName string, alloc v1.ResourceList)
	SetPodResourceAllocation(PodResourceAllocation)
	SetPodResizeState(podUID string, resizeState v1.ResourcesResizeStatus)
	SetResizeState(PodResizeState)
	Delete(podUID string, containerName string)
	ClearState()
}

// State interface provides methods for tracking and setting pod resource allocation
type State interface {
	Reader
	writer
}
