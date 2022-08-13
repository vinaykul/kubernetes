//go:build linux
// +build linux

/*
Copyright 2018 The Kubernetes Authors.

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

package kuberuntime

import (
	"k8s.io/kubernetes/pkg/kubelet/cm"
	"math"
)

const (
	milliCPUToCPU = 1000

	// 100000 is equivalent to 100usec
	quotaPeriod    = 100000
	minQuotaPeriod = 1000
)

// milliCPUToQuota converts milliCPU to CFS quota and period values
func milliCPUToQuota(milliCPU int64, period int64) (quota int64) {
	// CFS quota is measured in two values:
	//  - cfs_period_us=100usec (the amount of time to measure usage across given by period)
	//  - cfs_quota=20usec (the amount of cpu time allowed to be used across a period)
	// so in the above example, you are limited to 20% of a single CPU
	// for multi-cpu environments, you just scale equivalent amounts
	// see https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt for details
	if milliCPU == 0 {
		return
	}

	// we then convert your milliCPU to a value normalized over a period
	quota = (milliCPU * period) / milliCPUToCPU

	// quota needs to be a minimum of 1ms.
	if quota < minQuotaPeriod {
		quota = minQuotaPeriod
	}

	return
}

// sharesToMilliCPU converts CpuShares (cpu.shares) to milli-CPU value
// TODO(vinaykul,InPlacePodVerticalScaling): Address issue that sets min req/limit to 2m/10m before beta
// See: https://github.com/kubernetes/kubernetes/pull/102884#discussion_r662552642
func sharesToMilliCPU(shares int64) int64 {
	milliCPU := int64(0)
	if shares >= int64(cm.MinShares) {
		milliCPU = int64(math.Ceil(float64(shares*milliCPUToCPU) / float64(cm.SharesPerCPU)))
	}
	return milliCPU
}

// quotaToMilliCPU converts cpu.cfs_quota_us and cpu.cfs_period_us to milli-CPU value
func quotaToMilliCPU(quota int64, period int64) int64 {
	if quota == -1 {
		return int64(0)
	}
	return (quota * milliCPUToCPU) / period
}
