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
	"sync"

	"k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

type stateMemory struct {
	sync.RWMutex
	podAllocation  PodResourceAllocation
	podResizeState PodResizeState
}

var _ State = &stateMemory{}

// NewStateMemory creates new State to track resources allocated to pods
func NewStateMemory() State {
	klog.V(2).InfoS("Initialized new in-memory state store for pod resource allocation tracking")
	return &stateMemory{
		podAllocation:  PodResourceAllocation{},
		podResizeState: PodResizeState{},
	}
}

func (s *stateMemory) GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool) {
	s.RLock()
	defer s.RUnlock()

	res, ok := s.podAllocation[podUID][containerName]
	return res.DeepCopy(), ok
}

func (s *stateMemory) GetPodResourceAllocation() PodResourceAllocation {
	s.RLock()
	defer s.RUnlock()
	return s.podAllocation.Clone()
}

func (s *stateMemory) GetPodResizeState(podUID string) (v1.ResourcesResizeStatus, bool) {
	s.RLock()
	defer s.RUnlock()

	res, ok := s.podResizeState[podUID]
	return res, ok
}

func (s *stateMemory) GetResizeState() PodResizeState {
	s.RLock()
	defer s.RUnlock()
	prs := make(map[string]v1.ResourcesResizeStatus)
	for k, v := range s.podResizeState {
		prs[k] = v
	}
	return prs
}

func (s *stateMemory) SetContainerResourceAllocation(podUID string, containerName string, alloc v1.ResourceList) {
	s.Lock()
	defer s.Unlock()

	if _, ok := s.podAllocation[podUID]; !ok {
		s.podAllocation[podUID] = make(map[string]v1.ResourceList)
	}

	s.podAllocation[podUID][containerName] = alloc
	klog.V(3).InfoS("Updated container resource allocation", "podUID", podUID, "containerName", containerName, "alloc", alloc)
}

func (s *stateMemory) SetPodResourceAllocation(a PodResourceAllocation) {
	s.Lock()
	defer s.Unlock()

	s.podAllocation = a.Clone()
	klog.V(3).InfoS("Updated pod resource allocation", "allocation", a)
}

func (s *stateMemory) SetPodResizeState(podUID string, resizeState v1.ResourcesResizeStatus) {
	s.Lock()
	defer s.Unlock()

	if resizeState != "" {
		s.podResizeState[podUID] = resizeState
	} else {
		delete(s.podResizeState, podUID)
	}
	klog.V(3).InfoS("Updated pod resize state", "podUID", podUID, "resizeState", resizeState)
}

func (s *stateMemory) SetResizeState(rs PodResizeState) {
	s.Lock()
	defer s.Unlock()
	prs := make(map[string]v1.ResourcesResizeStatus)
	for k, v := range rs {
		prs[k] = v
	}
	s.podResizeState = prs
	klog.V(3).InfoS("Updated pod resize state", "resizes", rs)
}

func (s *stateMemory) deleteContainer(podUID string, containerName string) {
	delete(s.podAllocation[podUID], containerName)
	if len(s.podAllocation[podUID]) == 0 {
		delete(s.podAllocation, podUID)
		delete(s.podResizeState, podUID)
	}
	klog.V(3).InfoS("Deleted pod resource allocation", "podUID", podUID, "containerName", containerName)
}

func (s *stateMemory) Delete(podUID string, containerName string) {
	s.Lock()
	defer s.Unlock()
	if len(containerName) == 0 {
		for cName := range s.podAllocation[podUID] {
			s.deleteContainer(podUID, cName)
		}
	} else {
		s.deleteContainer(podUID, containerName)
	}
}

func (s *stateMemory) ClearState() {
	s.Lock()
	defer s.Unlock()

	s.podAllocation = make(PodResourceAllocation)
	s.podResizeState = make(PodResizeState)
	klog.V(3).InfoS("Cleared state")
}
