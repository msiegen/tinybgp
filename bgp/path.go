// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bgp

import (
	"net/netip"
	"sort"

	"golang.org/x/exp/slices"
)

// Path represents a single network path to a destination.
type Path struct {
	Peer        netip.Addr
	Nexthop     netip.Addr
	ASPath      []uint32
	Communities []uint32
}

func NewLocalPathV6(communities ...uint32) Path {
	return Path{
		Nexthop:     netip.IPv6Unspecified(),
		Communities: communities,
	}
}

// Equal checks for equality, ignoring the generation.
func (p Path) Equal(q Path) bool {
	return p.Peer == q.Peer &&
		p.Nexthop == q.Nexthop &&
		slices.Equal(p.ASPath, q.ASPath) &&
		slices.Equal(p.Communities, q.Communities)
}

// Contains checks whether the path contains the specified AS number.
func (p Path) Contains(asn uint32) bool {
	for _, hop := range p.ASPath {
		if hop == asn {
			return true
		}
	}
	return false
}

// SortPaths sorts the paths by the length of their ASPath, shortest first.
func SortPaths(ps []Path) {
	sort.SliceStable(ps, func(i, j int) bool {
		return len(ps[i].ASPath) < len(ps[j].ASPath)
	})
}
