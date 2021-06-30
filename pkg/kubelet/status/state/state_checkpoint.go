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
	"fmt"
	"path"
	"sync"

	"k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/kubelet/checkpointmanager"
	"k8s.io/kubernetes/pkg/kubelet/checkpointmanager/errors"
)

var _ State = &stateCheckpoint{}

type stateCheckpoint struct {
	mux               sync.RWMutex
	cache             State
	checkpointManager checkpointmanager.CheckpointManager
	checkpointName    string
}

// NewStateCheckpoint creates new State for keeping track of pod resource allocations with checkpoint backend
func NewStateCheckpoint(stateDir, checkpointName string) (State, error) {
	checkpointManager, err := checkpointmanager.NewCheckpointManager(stateDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize checkpoint manager for pod allocation tracking: %v", err)
	}
	stateCheckpoint := &stateCheckpoint{
		cache:             NewStateMemory(),
		checkpointManager: checkpointManager,
		checkpointName:    checkpointName,
	}

	if err := stateCheckpoint.restoreState(); err != nil {
		//lint:ignore ST1005 user-facing error message
		return nil, fmt.Errorf("could not restore state from checkpoint: %v, please drain this node and delete pod allocation checkpoint file %q before restarting Kubelet", err, path.Join(stateDir, checkpointName))
	}

	return stateCheckpoint, nil
}

// restores state from a checkpoint and creates it if it doesn't exist
func (sc *stateCheckpoint) restoreState() error {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	var err error

	checkpoint := NewPodResourceAllocationCheckpoint()

	if err = sc.checkpointManager.GetCheckpoint(sc.checkpointName, checkpoint); err != nil {
		if err == errors.ErrCheckpointNotFound {
			return sc.storeState()
		}
		return err
	}

	sc.cache.SetPodResourceAllocation(checkpoint.AllocationEntries)
	sc.cache.SetResizeState(checkpoint.ResizeStateEntries)
	klog.V(2).InfoS("State checkpoint: restored pod resource allocation state from checkpoint")

	return nil
}

// saves state to a checkpoint, caller is responsible for locking
func (sc *stateCheckpoint) storeState() error {
	checkpoint := NewPodResourceAllocationCheckpoint()

	podAllocation := sc.cache.GetPodResourceAllocation()
	for pod := range podAllocation {
		checkpoint.AllocationEntries[pod] = make(map[string]v1.ResourceList)
		for container, alloc := range podAllocation[pod] {
			checkpoint.AllocationEntries[pod][container] = alloc
		}
	}

	podResizeState := sc.cache.GetResizeState()
	checkpoint.ResizeStateEntries = make(map[string]v1.ResourcesResizeStatus)
	for pUID, rState := range podResizeState {
		checkpoint.ResizeStateEntries[pUID] = rState
	}

	err := sc.checkpointManager.CreateCheckpoint(sc.checkpointName, checkpoint)
	if err != nil {
		klog.ErrorS(err, "Failed to save pod allocation checkpoint")
		return err
	}
	return nil
}

// GetContainerResourceAllocation returns current resources allocated to a pod's container
func (sc *stateCheckpoint) GetContainerResourceAllocation(podUID string, containerName string) (v1.ResourceList, bool) {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	res, ok := sc.cache.GetContainerResourceAllocation(podUID, containerName)
	return res, ok
}

// GetPodResourceAllocation returns current pod resource allocation
func (sc *stateCheckpoint) GetPodResourceAllocation() PodResourceAllocation {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetPodResourceAllocation()
}

// GetPodResizeState returns the last resize decision for a pod
func (sc *stateCheckpoint) GetPodResizeState(podUID string) (v1.ResourcesResizeStatus, bool) {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetPodResizeState(podUID)
}

// GetResizeState returns the set of resize decisions made
func (sc *stateCheckpoint) GetResizeState() PodResizeState {
	sc.mux.RLock()
	defer sc.mux.RUnlock()
	return sc.cache.GetResizeState()
}

// SetContainerResourceAllocation sets resources allocated to a pod's container
func (sc *stateCheckpoint) SetContainerResourceAllocation(podUID string, containerName string, alloc v1.ResourceList) {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetContainerResourceAllocation(podUID, containerName, alloc)
	sc.storeState()
}

// SetPodResourceAllocation sets pod resource allocation
func (sc *stateCheckpoint) SetPodResourceAllocation(a PodResourceAllocation) {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetPodResourceAllocation(a)
	sc.storeState()
}

// SetPodResizeState sets the last resize decision for a pod
func (sc *stateCheckpoint) SetPodResizeState(podUID string, resizeState v1.ResourcesResizeStatus) {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetPodResizeState(podUID, resizeState)
	sc.storeState()
}

// SetResizeState sets the resize decisions
func (sc *stateCheckpoint) SetResizeState(rs PodResizeState) {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.SetResizeState(rs)
	sc.storeState()
}

// Delete deletes allocations for specified pod
func (sc *stateCheckpoint) Delete(podUID string, containerName string) {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.Delete(podUID, containerName)
	sc.storeState()
}

// ClearState clears the state and saves it in a checkpoint
func (sc *stateCheckpoint) ClearState() {
	sc.mux.Lock()
	defer sc.mux.Unlock()
	sc.cache.ClearState()
	sc.storeState()
}
