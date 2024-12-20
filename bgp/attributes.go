// Copyright 2024 Google LLC
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
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unique"
)

const (
	// DefaultLocalPreference is the default value of the local preference
	// for routes that do not specify one.
	DefaultLocalPreference uint32 = 100
)

// Attributes is the information associated with a route.
// Attributes are comparable and may be used as keys in a map.
type Attributes struct {
	// Peer is the BGP peer from which the route was received.
	Peer netip.Addr
	// Nexthop is the IP neighbor where packets traversing the route should be
	// sent. It's commonly equal to the peer address, but can differ e.g. if the
	// peer is a route server.
	Nexthop netip.Addr
	// LocalPref, together with HasLocalPref, specifies a priority for the route.
	// Higher values mean the route is more preferred. The local preference is
	// used in best path computations and may be set by an import filter, but is
	// not imported from or exported to peers (eBGP semantics).
	LocalPref uint32
	// HasLocalPref indicates whether LocalPref contains a valid local preference.
	// When false, a default local preference of 100 is assumed.
	HasLocalPref bool

	// path is the serialized AS path.
	path string
	// communities is the serialized set of communities.
	communities string
	// extendedCommunities is the serialized set of extended communities.
	extendedCommunities string
}

func deserializePath(s string) []uint32 {
	if s == "" {
		return nil
	}
	b := []byte(s)
	asns := make([]uint32, len(s)/4)
	for i := 0; i < len(asns); i++ {
		asns[i] = binary.LittleEndian.Uint32(b[4*i : 4*i+4])
	}
	return asns
}

// Path returns AS path. The first element is the nexthop
// and the last element is the route's origin.
func (a *Attributes) Path() []uint32 {
	return deserializePath(a.path)
}

func serializePath(asns []uint32) string {
	if len(asns) == 0 {
		return ""
	}
	b := make([]byte, 4*len(asns))
	for i, asn := range asns {
		binary.LittleEndian.PutUint32(b[4*i:4*i+4], asn)
	}
	return string(b)
}

// SetPath replaces the AS path. The first element is the nexthop
// and the last element is the route's origin.
func (a *Attributes) SetPath(asns []uint32) {
	a.path = serializePath(asns)
}

// PathLen returns the length of the AS path.
func (a *Attributes) PathLen() int {
	return len(a.path) / 4
}

// PathContains checks whether an AS is present in the path.
func (a *Attributes) PathContains(asn uint32) bool {
	for i := 0; i < len(a.path)/4; i++ {
		if asn == deserializePath(a.path[4*i : 4*i+4])[0] {
			return true
		}
	}
	return false
}

// First returns the first AS in the path (corresponding to the nexthop).
func (a *Attributes) First() uint32 {
	if len(a.path) == 0 {
		return 0
	}
	return deserializePath(a.path[:4])[0]
}

// Origin returns the ASN originating the route.
func (a *Attributes) Origin() uint32 {
	if len(a.path) == 0 {
		return 0
	}
	return deserializePath(a.path[len(a.path)-4:])[0]
}

// Prepend inserts ASNs to the beginning of the path.
func (a *Attributes) Prepend(asns ...uint32) {
	a.path = serializePath(asns) + a.path
}

func deserializeCommunities(s string) map[Community]bool {
	if s == "" {
		return nil
	}
	b := []byte(s)
	cs := map[Community]bool{}
	for i := 0; i < len(s)/4; i++ {
		cs[NewCommunity(binary.LittleEndian.Uint32(b[4*i:4*i+4]))] = true
	}
	return cs
}

// Communities returns the BGP communities as defined by
// https://datatracker.ietf.org/doc/html/rfc1997.
func (a *Attributes) Communities() map[Community]bool {
	return deserializeCommunities(a.communities)
}

func serializeCommunities(cs map[Community]bool) string {
	sorted := make([]Community, 0, len(cs))
	for c, ok := range cs {
		if ok {
			sorted = append(sorted, c)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Origin < sorted[j].Origin || sorted[i].Value < sorted[j].Value
	})
	b := make([]byte, 4*len(sorted))
	for i, c := range sorted {
		binary.LittleEndian.PutUint32(b[4*i:4*i+4], c.Uint32())
	}
	return string(b)
}

// SetCommunities sets the BGP communities as defined by
// https://datatracker.ietf.org/doc/html/rfc1997.
func (a *Attributes) SetCommunities(cs map[Community]bool) {
	a.communities = serializeCommunities(cs)
}

func deserializeExtendedCommunities(s string) map[ExtendedCommunity]bool {
	if s == "" {
		return nil
	}
	b := []byte(s)
	cs := map[ExtendedCommunity]bool{}
	for i := 0; i < len(s)/8; i++ {
		cs[ExtendedCommunity(binary.LittleEndian.Uint64(b[8*i:8*i+8]))] = true
	}
	return cs
}

// ExtendedCommunities returns the BGP communities as defined by
// https://datatracker.ietf.org/doc/html/rfc4360.
//
// NOTE: This is experimental. See the ExtendedCommunity type for details.
func (a *Attributes) ExtendedCommunities() map[ExtendedCommunity]bool {
	return deserializeExtendedCommunities(a.extendedCommunities)
}

func serializeExtendedCommunities(cs map[ExtendedCommunity]bool) string {
	sorted := make([]ExtendedCommunity, 0, len(cs))
	for c, ok := range cs {
		if ok {
			sorted = append(sorted, c)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	b := make([]byte, 8*len(sorted))
	for i, c := range sorted {
		binary.LittleEndian.PutUint64(b[8*i:8*i+8], uint64(c))
	}
	return string(b)
}

// SetExtendedCommunities sets the BGP communities as defined by
// https://datatracker.ietf.org/doc/html/rfc4360.
//
// NOTE: This is experimental. See the ExtendedCommunity type for details.
func (a *Attributes) SetExtendedCommunities(cs map[ExtendedCommunity]bool) {
	a.extendedCommunities = serializeExtendedCommunities(cs)
}

// localPref returns the effective value of the local preference,
// which may be the default value if no local preference is specified.
func (a *Attributes) localPref() uint32 {
	if a.HasLocalPref {
		return a.LocalPref
	}
	return DefaultLocalPreference
}

// sortAttributes sorts a slice of attributes by their local preference
// (highest value first). If the local preference between two paths is equal,
// the one with the shorter AS path sorts first.
func sortAttributes(as []unique.Handle[Attributes]) {
	sort.SliceStable(as, func(i, j int) bool {
		ai := as[i].Value()
		aj := as[j].Value()
		if ilp, jlp := ai.localPref(), aj.localPref(); ilp != jlp {
			return ilp > jlp
		}
		return ai.PathLen() < aj.PathLen()
	})
}

// String returns a human readable representation of a few key attributes.
func (a Attributes) String() string {
	var parts []string
	if a.Nexthop.IsValid() {
		parts = append(parts, "nexthop="+a.Nexthop.String())
	}
	if a.path != "" {
		parts = append(parts, fmt.Sprintf("path=%v", a.Path()))
	}
	return "{" + strings.Join(parts, " ") + "}"
}
