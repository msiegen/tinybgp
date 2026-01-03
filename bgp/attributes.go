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
	"slices"
	"sort"
	"strings"
	"unique"
)

const (
	// DefaultLocalPreference is the default value of the local preference
	// for routes that do not specify one.
	DefaultLocalPreference uint32 = 100
)

// otherAttributes holds most of the information associated with a route, but
// not the AS path. These attributes are grouped for canonicalization because
// there are relatively few unique combinations in a typical routing table.
type otherAttributes struct {
	// peer is the BGP peer from which the route was received.
	peer netip.Addr
	// nexthop is the IP neighbor where packets should be sent.
	nexthop netip.Addr
	// localPref and hasLocalPref specify the local preference.
	localPref    uint32
	hasLocalPref bool
	// med and hasMED specify the multi exit discriminator.
	med    uint32
	hasMED bool
	// communities is the serialized set of communities.
	communities string
	// extendedCommunities is the serialized set of extended communities.
	extendedCommunities string
	// largeCommunities is the serialized set of large communities.
	largeCommunities string
}

// otherAttributesHandle represents a canonicalized otherAttributes value.
type otherAttributesHandle = unique.Handle[otherAttributes]

// Attributes is the information associated with a route.
// Attributes are comparable and may be used as keys in a map.
type Attributes struct {
	// otherAttributes holds everything except the path.
	otherAttributes otherAttributesHandle
	// path is the serialized AS path.
	path string
}

// attrHandle represents a canonicalized Attributes value.
type attrHandle = unique.Handle[Attributes]

// attributesBuilder provides a convenient way to create an Attributes.
type attributesBuilder struct {
	Peer                netip.Addr
	Nexthop             netip.Addr
	LocalPref           uint32
	HasLocalPref        bool
	MED                 uint32
	HasMED              bool
	Path                []uint32
	Communities         map[Community]bool
	ExtendedCommunities map[ExtendedCommunity]bool
	LargeCommunities    map[LargeCommunity]bool
}

func (b attributesBuilder) Build() Attributes {
	return Attributes{
		otherAttributes: unique.Make(otherAttributes{
			peer:                b.Peer,
			nexthop:             b.Nexthop,
			localPref:           b.LocalPref,
			hasLocalPref:        b.HasLocalPref,
			med:                 b.MED,
			hasMED:              b.HasMED,
			communities:         serializeCommunities(b.Communities),
			extendedCommunities: serializeExtendedCommunities(b.ExtendedCommunities),
			largeCommunities:    serializeLargeCommunities(b.LargeCommunities),
		}),
		path: serializePath(b.Path),
	}
}

// Peer returns the BGP peer from which the route was received.
func (a Attributes) Peer() netip.Addr {
	if a.otherAttributes != (otherAttributesHandle{}) {
		return a.otherAttributes.Value().peer
	}
	return netip.Addr{}
}

// SetPeer sets the BGP peer from which the route was received.
func (a *Attributes) SetPeer(peer netip.Addr) {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.peer = peer
	a.otherAttributes = unique.Make(oa)
}

// Nexthop returns the IP neighbor where packets traversing the route should be
// sent. It's commonly equal to the peer address, but can differ e.g. if the
// peer is a route server.
func (a Attributes) Nexthop() netip.Addr {
	if a.otherAttributes != (otherAttributesHandle{}) {
		return a.otherAttributes.Value().nexthop
	}
	return netip.Addr{}
}

// SetNexthop sets IP neighbor where packets traversing the route should be sent.
func (a *Attributes) SetNexthop(nh netip.Addr) {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.nexthop = nh
	a.otherAttributes = unique.Make(oa)
}

func (a *Attributes) setAddresses(peer, nexthop netip.Addr) {
	a.otherAttributes = unique.Make(otherAttributes{
		peer:    peer,
		nexthop: nexthop,
	})
}

// LocalPref returns the local preference, a priority for the route that is
// considered prior to the AS path length. Higher values are more preferred.
// If absent, a default value of 100 is returned and the boolean will be false.
// The local preference is used in best path computations and may be set by an
// import filter, but is not imported from or exported to peers (eBGP semantics).
func (a Attributes) LocalPref() (uint32, bool) {
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa := a.otherAttributes.Value()
		if oa.hasLocalPref {
			return oa.localPref, true
		}
	}
	return DefaultLocalPreference, false
}

// SetLocalPref sets the local preference. See the documentation for the
// LocalPref method to see how this is used.
func (a *Attributes) SetLocalPref(v uint32) {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.localPref = v
	oa.hasLocalPref = true
	a.otherAttributes = unique.Make(oa)
}

// ClearLocalPref clears the local preference. See the documentation for the
// LocalPref method to see how this is used.
func (a *Attributes) ClearLocalPref() {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.localPref = 0
	oa.hasLocalPref = false
	a.otherAttributes = unique.Make(oa)
}

// MED returns the multi exit discriminator, which specifies a priority that is
// used to break a tie between two routes with the same AS path length and same
// first AS in the path. Lower values are more preferred. The default is zero.
// MED is imported from peers if they provide it, and cleared by the default
// export filter (eBGP semantics).
func (a Attributes) MED() (uint32, bool) {
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa := a.otherAttributes.Value()
		return oa.med, oa.hasMED
	}
	return 0, false
}

// SetMED sets the multi exit discriminator. See the documentation for the
// MED method to see how this is used.
func (a *Attributes) SetMED(v uint32) {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.med = v
	oa.hasMED = true
	a.otherAttributes = unique.Make(oa)
}

// ClearMED clears the multi exit discriminator. See the documentation for the
// MED method to see how this is used.
func (a *Attributes) ClearMED() {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.med = 0
	oa.hasMED = false
	a.otherAttributes = unique.Make(oa)
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
func (a Attributes) Path() []uint32 {
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
func (a Attributes) PathContains(asn uint32) bool {
	for i := 0; i < len(a.path)/4; i++ {
		if asn == deserializePath(a.path[4*i : 4*i+4])[0] {
			return true
		}
	}
	return false
}

// First returns the first AS in the path (corresponding to the nexthop).
func (a Attributes) First() uint32 {
	if len(a.path) == 0 {
		return 0
	}
	return deserializePath(a.path[:4])[0]
}

// Origin returns the ASN originating the route.
func (a Attributes) Origin() uint32 {
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
func (a Attributes) Communities() map[Community]bool {
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa := a.otherAttributes.Value()
		return deserializeCommunities(oa.communities)
	}
	return nil
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
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.communities = serializeCommunities(cs)
	a.otherAttributes = unique.Make(oa)
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
func (a Attributes) ExtendedCommunities() map[ExtendedCommunity]bool {
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa := a.otherAttributes.Value()
		return deserializeExtendedCommunities(oa.extendedCommunities)
	}
	return nil
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
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.extendedCommunities = serializeExtendedCommunities(cs)
	a.otherAttributes = unique.Make(oa)
}

func deserializeLargeCommunities(s string) map[LargeCommunity]bool {
	if s == "" {
		return nil
	}
	b := []byte(s)
	cs := map[LargeCommunity]bool{}
	for i := 0; i < len(s)/12; i++ {
		cs[LargeCommunity{
			binary.LittleEndian.Uint32(b[12*i : 12*i+4]),
			binary.LittleEndian.Uint32(b[12*i+4 : 12*i+8]),
			binary.LittleEndian.Uint32(b[12*i+8 : 12*i+12]),
		}] = true
	}
	return cs
}

// LargeCommunities returns the BGP large communities as defined by
// https://datatracker.ietf.org/doc/html/rfc8092
func (a Attributes) LargeCommunities() map[LargeCommunity]bool {
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa := a.otherAttributes.Value()
		return deserializeLargeCommunities(oa.largeCommunities)
	}
	return nil
}

func serializeLargeCommunities(cs map[LargeCommunity]bool) string {
	sorted := make([]LargeCommunity, 0, len(cs))
	for c, ok := range cs {
		if ok {
			sorted = append(sorted, c)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].LessThan(sorted[j])
	})
	b := make([]byte, 12*len(sorted))
	for i, c := range sorted {
		binary.LittleEndian.PutUint32(b[12*i:12*i+4], c.ASN)
		binary.LittleEndian.PutUint32(b[12*i+4:12*i+8], c.Data1)
		binary.LittleEndian.PutUint32(b[12*i+8:12*i+12], c.Data2)
	}
	return string(b)
}

// SetLargeCommunities sets the BGP communities as defined by
// https://datatracker.ietf.org/doc/html/rfc8092
func (a *Attributes) SetLargeCommunities(cs map[LargeCommunity]bool) {
	var oa otherAttributes
	if a.otherAttributes != (otherAttributesHandle{}) {
		oa = a.otherAttributes.Value()
	}
	oa.largeCommunities = serializeLargeCommunities(cs)
	a.otherAttributes = unique.Make(oa)
}

// String returns a human readable representation of a few key attributes.
func (a Attributes) String() string {
	var parts []string
	if nh := a.Nexthop(); nh.IsValid() {
		parts = append(parts, "nexthop="+nh.String())
	}
	if a.path != "" {
		parts = append(parts, fmt.Sprintf("path=%v", a.Path()))
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// Compare decides which attributes represent the better route. It returns a
// negative number if a is better than b, a positive number if b is better than
// a, and zero if a and b are equally good. Better routes are identified by:
//   - Local preference (higher values first)
//   - AS path length (shorter paths first)
//   - MED (lower values first)
func Compare(a, b Attributes) int {
	alp, _ := a.LocalPref()
	blp, _ := b.LocalPref()
	if alp > blp {
		return -1
	} else if alp < blp {
		return 1
	}
	if apl, bpl := a.PathLen(), b.PathLen(); apl < bpl {
		return -1
	} else if apl > bpl {
		return 1
	}
	am, aHasMED := a.MED()
	bm, bHasMED := b.MED()
	if (aHasMED || bHasMED) && (a.First() == b.First()) {
		if am < bm {
			return -1
		} else if am > bm {
			return 1
		}
	}
	return 0
}

// sortAttributes sorts a slice of attributes to place the best routes first.
func sortAttributes(as []attrHandle, cmp func(a, b Attributes) int) {
	slices.SortStableFunc(as, func(a, b attrHandle) int {
		return cmp(a.Value(), b.Value())
	})
}
