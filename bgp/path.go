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
	// Peer is the BGP neighbor from which this path was received.
	Peer netip.Addr
	// Nexthop is the IP neighbor where packets traversing the path should be
	// sent. It's commonly equal to the peer address, but can differ e.g. if the
	// peer is a route server.
	Nexthop netip.Addr
	// LocalPref specifies a priority for the path. Higher values mean the path
	// is more preferred.
	LocalPref int
	// ASPath is a slice of ASNs. The first element is the nexthop and the last
	// element is the path's origin.
	ASPath []uint32
	// Communities are BGP communities as defined by
	// https://datatracker.ietf.org/doc/html/rfc1997.
	Communities []Community
}

// Equal checks for equality, ignoring the generation.
func (p Path) Equal(q Path) bool {
	return p.Peer == q.Peer &&
		p.Nexthop == q.Nexthop &&
		slices.Equal(p.ASPath, q.ASPath) &&
		slices.Equal(p.Communities, q.Communities)
}

// Contains checks whether the path contains the given AS number.
func (p Path) Contains(asn uint32) bool {
	for _, hop := range p.ASPath {
		if hop == asn {
			return true
		}
	}
	return false
}

// SortPaths sorts the paths by their local preference (highest value first). If
// the local preference between two paths is equal, the one with the shorter AS
// path sorts first.
func SortPaths(ps []Path) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].LocalPref == ps[j].LocalPref {
			return len(ps[i].ASPath) < len(ps[j].ASPath)
		}
		return ps[i].LocalPref > ps[j].LocalPref
	})
}
