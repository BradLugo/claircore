package spdx

import (
	"container/heap"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type claircoreRecord int

const (
	claircorePackage claircoreRecord = iota
	claircoreDistribution
	claircoreRepository
)

type orderableSpdxPackage struct {
	recordType claircoreRecord
	id         int
	pkg        *v2_3.Package
}

type spdxPackageHeap []orderableSpdxPackage

var _ heap.Interface = (*spdxPackageHeap)(nil)

func (h spdxPackageHeap) Len() int { return len(h) }
func (h spdxPackageHeap) Less(i, j int) bool {
	return h[i].recordType < h[j].recordType || h[i].recordType == h[j].recordType && h[i].id < h[j].id
}
func (h spdxPackageHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *spdxPackageHeap) Push(x any) {
	*h = append(*h, x.(orderableSpdxPackage))
}

func (h *spdxPackageHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
