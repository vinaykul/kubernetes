/*
Copyright 2020 The Kubernetes Authors.

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
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/diff"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"
	kubecm "k8s.io/kubernetes/pkg/kubelet/cm"

	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	imageutils "k8s.io/kubernetes/test/utils/image"

	"github.com/onsi/ginkgo"
)

const (
	InPlacePodVerticalScalingFeature featuregate.Feature = "InPlacePodVerticalScaling"

	CgroupCPUPeriod string = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
	CgroupCPUShares string = "/sys/fs/cgroup/cpu/cpu.shares"
	CgroupCPUQuota  string = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
	CgroupMemLimit  string = "/sys/fs/cgroup/memory/memory.limit_in_bytes"

	PollInterval time.Duration = 2 * time.Second
	// PollTimeout  time.Duration = time.Minute
	PollTimeout  time.Duration = 5 * time.Minute
)

type ContainerResources struct {
	CPUReq, CPULim, MemReq, MemLim, EphStorReq, EphStorLim string
}

type ContainerAllocations struct {
	CPUAlloc, MemAlloc, ephStorAlloc string
}

type TestContainerInfo struct {
	Name        string
	Resources   *ContainerResources
	Allocations *ContainerAllocations
	CPUPolicy   *v1.ContainerResizePolicy
	MemPolicy   *v1.ContainerResizePolicy
	RestartCnt	int32
}

func makeTestContainer(tcInfo TestContainerInfo) v1.Container {
	var res v1.ResourceRequirements
	var alloc v1.ResourceList
	var resizePol []v1.ResizePolicy
	cmd := "trap exit TERM; while true; do sleep 1; done"

	if tcInfo.Resources != nil {
		res = v1.ResourceRequirements{
			Limits:   make(v1.ResourceList),
			Requests: make(v1.ResourceList),
		}
		if tcInfo.Resources.CPULim != "" {
			res.Limits[v1.ResourceCPU] = resource.MustParse(tcInfo.Resources.CPULim)
		}
		if tcInfo.Resources.MemLim != "" {
			res.Limits[v1.ResourceMemory] = resource.MustParse(tcInfo.Resources.MemLim)
		}
		if tcInfo.Resources.EphStorLim != "" {
			res.Limits[v1.ResourceEphemeralStorage] = resource.MustParse(tcInfo.Resources.EphStorLim)
		}
		if tcInfo.Resources.CPUReq != "" {
			res.Requests[v1.ResourceCPU] = resource.MustParse(tcInfo.Resources.CPUReq)
		}
		if tcInfo.Resources.MemReq != "" {
			res.Requests[v1.ResourceMemory] = resource.MustParse(tcInfo.Resources.MemReq)
		}
		if tcInfo.Resources.EphStorReq != "" {
			res.Requests[v1.ResourceEphemeralStorage] = resource.MustParse(tcInfo.Resources.EphStorReq)
		}
	}
	if tcInfo.Allocations != nil {
		alloc = make(v1.ResourceList)
		if tcInfo.Allocations.CPUAlloc != "" {
			alloc[v1.ResourceCPU] = resource.MustParse(tcInfo.Allocations.CPUAlloc)
		}
		if tcInfo.Allocations.MemAlloc != "" {
			alloc[v1.ResourceMemory] = resource.MustParse(tcInfo.Allocations.MemAlloc)
		}
		if tcInfo.Allocations.ephStorAlloc != "" {
			alloc[v1.ResourceEphemeralStorage] = resource.MustParse(tcInfo.Allocations.ephStorAlloc)
		}

	}
	if tcInfo.CPUPolicy != nil {
		cpuPol := v1.ResizePolicy{ResourceName: v1.ResourceCPU, Policy: *tcInfo.CPUPolicy}
		resizePol = append(resizePol, cpuPol)
	}
	if tcInfo.MemPolicy != nil {
		memPol := v1.ResizePolicy{ResourceName: v1.ResourceMemory, Policy: *tcInfo.MemPolicy}
		resizePol = append(resizePol, memPol)
	}

	tc := v1.Container{
		Name:               tcInfo.Name,
		Image:              imageutils.GetE2EImage(imageutils.BusyBox),
		Command:            []string{"/bin/sh"},
		Args:               []string{"-c", cmd},
		Resources:          res,
		ResourcesAllocated: alloc,
		ResizePolicy:       resizePol,
	}
	return tc
}

func makeTestPod(ns, name, timeStamp string, tcInfo []TestContainerInfo) *v1.Pod {
	var testContainers []v1.Container
	for _, ci := range tcInfo {
		tc := makeTestContainer(ci)
		testContainers = append(testContainers, tc)
	}
	pod := &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"name": "fooPod",
				"time": timeStamp,
			},
		},
		Spec: v1.PodSpec{
			Containers:    testContainers,
			RestartPolicy: v1.RestartPolicyOnFailure,
		},
	}
	return pod
}

func verifyPodResizePolicy(pod *v1.Pod, tcInfo []TestContainerInfo) {
	cMap := make(map[string]*v1.Container)
	for i, c := range pod.Spec.Containers {
		cMap[c.Name] = &pod.Spec.Containers[i]
	}
	for _, ci := range tcInfo {
		c, found := cMap[ci.Name]
		framework.ExpectEqual(found, true)
		tc := makeTestContainer(ci)
		framework.ExpectEqual(c.ResizePolicy, tc.ResizePolicy)
	}
}

func verifyPodResources(pod *v1.Pod, tcInfo []TestContainerInfo) {
	cMap := make(map[string]*v1.Container)
	for i, c := range pod.Spec.Containers {
		cMap[c.Name] = &pod.Spec.Containers[i]
	}
	for _, ci := range tcInfo {
		c, found := cMap[ci.Name]
		framework.ExpectEqual(found, true)
		tc := makeTestContainer(ci)
		framework.ExpectEqual(c.Resources, tc.Resources)
	}
}

func verifyPodAllocations(pod *v1.Pod, tcInfo []TestContainerInfo) {
	cMap := make(map[string]*v1.Container)
	for i, c := range pod.Spec.Containers {
		cMap[c.Name] = &pod.Spec.Containers[i]
	}
	for _, ci := range tcInfo {
		c, found := cMap[ci.Name]
		framework.ExpectEqual(found, true)
		if ci.Allocations == nil {
			alloc := &ContainerAllocations{CPUAlloc: ci.Resources.CPUReq, MemAlloc: ci.Resources.MemReq}
			ci.Allocations = alloc
			defer func() {
				ci.Allocations = nil
			}()
		}
		tc := makeTestContainer(ci)
		framework.ExpectEqual(c.ResourcesAllocated, tc.ResourcesAllocated)
	}
}

func verifyPodStatusResources(pod *v1.Pod, tcInfo []TestContainerInfo) {
	csMap := make(map[string]*v1.ContainerStatus)
	for i, c := range pod.Status.ContainerStatuses {
		csMap[c.Name] = &pod.Status.ContainerStatuses[i]
	}

	for _, ci := range tcInfo {
		cs, found := csMap[ci.Name]
		framework.ExpectEqual(found, true)

		// Fixed the testing error for container specifying memory only, added by chenw.
		// When creating a container in a pod without specifying the CPUReq,  its Resource.CPUReq automatically became "2m"
		if ci.Resources.CPUReq == "" {
			ci.Resources.CPUReq = "2m"
		}

		tc := makeTestContainer(ci)
		framework.ExpectEqual(cs.Resources, tc.Resources)

		// Added by chenw, verify the restart count of the container.
		framework.ExpectEqual(cs.RestartCount, ci.RestartCnt)
	}
}

func verifyPodContainersCgroupConfig(pod *v1.Pod, tcInfo []TestContainerInfo) {
	verifyCgroupValue := func(cName, cgPath, expectedCgValue string) {
		cmd := []string{"head", "-n", "1", cgPath}
		cgValue, err := framework.LookForStringInPodExecToContainer(pod.Namespace, pod.Name, cName, cmd, expectedCgValue, PollTimeout)
		framework.Logf(cgValue)
		framework.ExpectNoError(err, "failed to find expected cgroup value in container")
		cgValue = strings.Trim(cgValue, "\n")
		framework.Logf(cgValue)
		framework.Logf(expectedCgValue)
		framework.ExpectEqual(cgValue, expectedCgValue)
	}
	for _, ci := range tcInfo {
		if ci.Resources == nil {
			continue
		}
		tc := makeTestContainer(ci)
		if tc.Resources.Limits != nil || tc.Resources.Requests != nil {
			var cpuShares int64
			memLimitInBytes := tc.Resources.Limits.Memory().Value()
			cpuRequest := tc.Resources.Requests.Cpu()
			cpuLimit := tc.Resources.Limits.Cpu()
			if cpuRequest.IsZero() && !cpuLimit.IsZero() {
				cpuShares = int64(kubecm.MilliCPUToShares(cpuLimit.MilliValue()))
			} else {
				cpuShares = int64(kubecm.MilliCPUToShares(cpuRequest.MilliValue()))
			}

			cpuQuota := kubecm.MilliCPUToQuota(cpuLimit.MilliValue(), kubecm.QuotaPeriod)

			// Added by chenw. Verify the CPU shares only when the pod QoS is guaranteed.
			//if (pod.Status.QOSClass == v1.PodQOSGuaranteed) {
			if !cpuLimit.IsZero() || !cpuRequest.IsZero() {
				verifyCgroupValue(ci.Name, CgroupCPUShares, strconv.FormatInt(cpuShares, 10))
			}
			//}

			if !cpuLimit.IsZero() {
				verifyCgroupValue(ci.Name, CgroupCPUQuota, strconv.FormatInt(cpuQuota, 10))
			}

			// Added by chenw. If memory is not specified, the value in memLimitInBytes would be 0.
			if (memLimitInBytes > 0) {
				verifyCgroupValue(ci.Name, CgroupMemLimit, strconv.FormatInt(memLimitInBytes, 10))
			}
		}
	}
}

var _ = ginkgo.Describe("[sig-node] PodInPlaceResize", func() {
	f := framework.NewDefaultFramework("pod-resize")
	var podClient *framework.PodClient
	var ns string

	if !utilfeature.DefaultFeatureGate.Enabled(InPlacePodVerticalScalingFeature) {
	//	return
	}

	ginkgo.BeforeEach(func() {
		podClient = f.PodClient()
		ns = f.Namespace.Name
	})

	type testCase struct {
		name        string
		containers  []TestContainerInfo
		patchString string
		expected    []TestContainerInfo
	}

	noRestart := v1.NoRestart
	tests := []testCase{
		{
			name: "Guaranteed QoS pod, one container - increase CPU & memory",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "100m", MemReq: "200Mi", MemLim: "200Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"200m","memory":"400Mi"},"limits":{"cpu":"200m","memory":"400Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "200m", MemReq: "400Mi", MemLim: "400Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Guaranteed QoS pod, one container - decrease CPU & memory",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "300m", CPULim: "300m", MemReq: "500Mi", MemLim: "500Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"100m","memory":"250Mi"},"limits":{"cpu":"100m","memory":"250Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "100m", MemReq: "250Mi", MemLim: "250Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Guaranteed QoS pod, three containers (c1, c2, c3) - increase: CPU (c1,c3), memory (c2) ; decrease: CPU (c2), memory (c1,c3)",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "100m", MemReq: "100Mi", MemLim: "100Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
				{
					Name:      "c2",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "200m", MemReq: "200Mi", MemLim: "200Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
				{
					Name:      "c3",
					Resources: &ContainerResources{CPUReq: "300m", CPULim: "300m", MemReq: "300Mi", MemLim: "300Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"140m","memory":"50Mi"},"limits":{"cpu":"140m","memory":"50Mi"}}},
				{"name":"c2", "resources":{"requests":{"cpu":"150m","memory":"240Mi"},"limits":{"cpu":"150m","memory":"240Mi"}}},
				{"name":"c3", "resources":{"requests":{"cpu":"340m","memory":"250Mi"},"limits":{"cpu":"340m","memory":"250Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "140m", CPULim: "140m", MemReq: "50Mi", MemLim: "50Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
				{
					Name:      "c2",
					Resources: &ContainerResources{CPUReq: "150m", CPULim: "150m", MemReq: "240Mi", MemLim: "240Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
				{
					Name:      "c3",
					Resources: &ContainerResources{CPUReq: "340m", CPULim: "340m", MemReq: "250Mi", MemLim: "250Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		// By chenw, adding E2E test cases 3 for Burstable class single container Pod that specifies both CPU & memory
		{
			name: "Bustable class pod, one container - increase CPU & memory requests",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "400m", MemReq: "128Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"200m","memory":"256Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "400m", MemReq: "256Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Bustable class pod, one container - decrease CPU & memory requests",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "400m", MemReq: "256Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"100m","memory":"128Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "400m", MemReq: "128Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		// By chenw, adding E2E test cases 6 for Burstable class single container Pod that specifies both CPU & memory
		{
			name: "Bustable class pod, one container - increase CPU & memory limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "200m", MemReq: "128Mi", MemLim: "256Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"limits":{"cpu":"400m","memory":"512Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "400m", MemReq: "128Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Bustable class pod, one container - decrease CPU & memory limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "400m", MemReq: "128Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"limits":{"cpu":"200m","memory":"256Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "200m", MemReq: "128Mi", MemLim: "256Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		// By chenw, adding E2E test cases 9 for Burstable class single container Pod that specifies both CPU & memory
		{
			name: "Bustable class pod, one container - increase CPU & memory requests & limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "200m", MemReq: "128Mi", MemLim: "256Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"200m","memory":"256Mi"},"limits":{"cpu":"400m","memory":"512Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "400m", MemReq: "256Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Bustable class pod, one container - decrease CPU & memory requests & limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "400m", MemReq: "256Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"100m","memory":"128Mi"},"limits":{"cpu":"200m","memory":"256Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "200m", MemReq: "128Mi", MemLim: "256Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		// By chenw, adding E2E test case 3 for Burstable class single container Pod that specifies CPU only
		{
			name: "Bustable class pod, one container specifying CPU only - increase CPU requests & limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "200m"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"200m"},"limits":{"cpu":"400m"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "400m"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Bustable class pod, one container specifying CPU only - decrease CPU requests & limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "200m", CPULim: "400m"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"cpu":"100m"},"limits":{"cpu":"200m"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{CPUReq: "100m", CPULim: "200m"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		// By chenw, adding E2E test case 3 for Burstable class single container Pod that specifies memory only
		{
			name: "Bustable class pod, one container that specifies memory only - increase memory requests & limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{MemReq: "128Mi", MemLim: "256Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"memory":"256Mi"},"limits":{"memory":"512Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{MemReq: "256Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
		{
			name: "Bustable class pod, one container that specifies memory only - decrease memory requests & limits",
			containers: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{MemReq: "256Mi", MemLim: "512Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
			patchString: `{"spec":{"containers":[
				{"name":"c1", "resources":{"requests":{"memory":"128Mi"},"limits":{"memory":"256Mi"}}}
			]}}`,
			expected: []TestContainerInfo{
				{
					Name:      "c1",
					Resources: &ContainerResources{MemReq: "128Mi", MemLim: "256Mi"},
					CPUPolicy: &noRestart,
					MemPolicy: &noRestart,
					RestartCnt: 0,
				},
			},
		},
	}

	for idx := range tests {
		tc := tests[idx]
		ginkgo.It(tc.name, func() {
			tStamp := strconv.Itoa(time.Now().Nanosecond())
			tPod := makeTestPod(ns, "testpod", tStamp, tc.containers)

			ginkgo.By("creating pod")
			pod := podClient.CreateSync(tPod)

			ginkgo.By("verifying the pod is in kubernetes")
			selector := labels.SelectorFromSet(labels.Set(map[string]string{"time": tStamp}))
			options := metav1.ListOptions{LabelSelector: selector.String()}
			pods, err := podClient.List(context.TODO(), options)
			framework.ExpectNoError(err, "failed to query for pods")
			framework.ExpectEqual(len(pods.Items), 1)

			ginkgo.By("verifying pod resources and allocations are as expected")
			verifyPodResources(pod, tc.containers)
			verifyPodAllocations(pod, tc.containers)
			verifyPodResizePolicy(pod, tc.containers)

			ginkgo.By("verifying pod status resources are as expected")
			verifyPodStatusResources(pod, tc.containers)

			ginkgo.By("patching pod for resize")
			pPod, pErr := f.ClientSet.CoreV1().Pods(pod.Namespace).Patch(context.TODO(), pod.Name,
				types.StrategicMergePatchType, []byte(tc.patchString), metav1.PatchOptions{})
			framework.ExpectNoError(pErr, "failed to patch pod for resize")

			ginkgo.By("verifying pod patched for resize")
			verifyPodResources(pPod, tc.expected)
			verifyPodAllocations(pPod, tc.containers)

			ginkgo.By("verifying cgroup configuration in containers")
			verifyPodContainersCgroupConfig(pPod, tc.expected)

			ginkgo.By("verifying pod resources, allocations, and status after resize")
			waitPodStatusResourcesEqualSpecResources := func() (*v1.Pod, error) {
				for start := time.Now(); time.Since(start) < PollTimeout; time.Sleep(PollInterval) {
					pod, err := podClient.Get(context.TODO(), pod.Name, metav1.GetOptions{})
					if err != nil {
						return nil, err
					}
					differs := false
					for idx, c := range pod.Spec.Containers {
						if diff.ObjectDiff(c.Resources, pod.Status.ContainerStatuses[idx].Resources) != "" {
							differs = true
							break
						}
					}
					if differs {
						continue
					}
					return pod, nil
				}
				return nil, fmt.Errorf("timed out waiting for pod spec resources to match status resources")
			}
			rPod, rErr := waitPodStatusResourcesEqualSpecResources()
			framework.ExpectNoError(rErr, "failed to get pod")
			verifyPodResources(rPod, tc.expected)
			verifyPodAllocations(rPod, tc.expected)
			verifyPodStatusResources(rPod, tc.expected)

			ginkgo.By("deleting pod")
			err = e2epod.DeletePodWithWait(f.ClientSet, pod)
			framework.ExpectNoError(err, "failed to delete pod")
		})
	}
})
