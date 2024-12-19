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
	"fmt"
	"net/netip"
	"testing"
	"unique"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestSerializeDeserializePath(t *testing.T) {
	for _, tc := range [][]uint32{
		{1, 2, 3},
		{4, 5, 6, 7, 8, 9},
	} {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			ser := serializePath(tc)
			got := deserializePath(ser)
			if diff := cmp.Diff(tc, got); diff != "" {
				t.Errorf("path mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAttributesPath(t *testing.T) {
	// Create attributes with no path.
	attrs := Attributes{}
	if g := attrs.PathLen(); g != 0 {
		t.Errorf("got initial path len %v, want 0", g)
	}
	if g := attrs.Path(); g != nil {
		t.Errorf("got initial path %v, want nil", g)
	}

	// Set a path.
	want := []uint32{64512, 4200000513, 64514}
	attrs.SetPath(want)
	if diff := cmp.Diff(want, attrs.Path()); diff != "" {
		t.Errorf("path mismatch (-want +got):\n%s", diff)
	}

	// Path should contain all the ASNs.
	for _, w := range want {
		if !attrs.PathContains(w) {
			t.Errorf("path does not contains %v", w)
		}
	}

	// Path should not contain any other ASN.
	for _, w := range []uint32{64555, 4200000555} {
		if attrs.PathContains(w) {
			t.Errorf("path should not contain %v", w)
		}
	}

	// Prepend an ASN.
	attrs.Prepend(4200000888)
	want = []uint32{4200000888, 64512, 4200000513, 64514}
	if diff := cmp.Diff(want, attrs.Path()); diff != "" {
		t.Errorf("path mismatch (-want +got):\n%s", diff)
	}

	// Check the length.
	if g := attrs.PathLen(); g != 4 {
		t.Errorf("got path length %v, want 4", g)
	}

	// Origin should be the last ASN.
	if g := attrs.Origin(); g != 64514 {
		t.Errorf("got origin %v, want 64514", g)
	}
}

func TestSerializeDeserializeCommunities(t *testing.T) {
	for _, tc := range []map[Community]bool{
		{Community{1, 2}: true, Community{3, 4}: true},
		{Community{2, 1}: true, Community{4, 3}: true},
		{Community{10000, 20000}: true, Community{30000, 40000}: true},
	} {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			ser := serializeCommunities(tc)
			got := deserializeCommunities(ser)
			if diff := cmp.Diff(tc, got); diff != "" {
				t.Errorf("communities mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAttributesCommunities(t *testing.T) {
	// Create attributes with no communities.
	attrs := Attributes{}
	cs := attrs.Communities()
	if cs != nil {
		t.Errorf("got initial empty communities map %v, want nil", cs)
	}

	// Set an empty map.
	cs = map[Community]bool{}
	attrs.SetCommunities(cs)
	cs = attrs.Communities()
	if cs != nil {
		t.Errorf("got modified empty communities map %v, want nil", cs)
	}

	// Set a map with only false values.
	c12 := Community{1, 2}
	cs = map[Community]bool{c12: false}
	attrs.SetCommunities(cs)
	cs = attrs.Communities()
	if cs != nil {
		t.Errorf("got modified empty communities map with false entries %v, want nil", cs)
	}

	// Add one community.
	cs = map[Community]bool{}
	cs[c12] = true
	attrs.SetCommunities(cs)

	// Add two more communities.
	c34 := Community{3, 4}
	c56 := Community{5, 6}
	cs = attrs.Communities()
	cs[c34] = true
	cs[c56] = true
	attrs.SetCommunities(cs)

	// Verify that the first community is present.
	cs = attrs.Communities()
	if !cs[c12] {
		t.Errorf("got %v=%v, want true", c12, false)
	}

	// Remove the first community.
	delete(cs, c12)
	attrs.SetCommunities(cs)
	cs = attrs.Communities()
	if cs[c12] {
		t.Errorf("got %v=%v, want false", c12, true)
	}

	// Verify that the second and third community are present.
	if !cs[c34] {
		t.Errorf("got %v=%v, want true", c34, false)
	}
	if !cs[c56] {
		t.Errorf("got %v=%v, want true", c56, false)
	}
}

func TestSortAttributes(t *testing.T) {
	a1 := Attributes{LocalPref: 200, HasLocalPref: true}
	a1.SetPath([]uint32{1, 2, 3, 4, 5})
	a2 := Attributes{LocalPref: 100, HasLocalPref: true}
	a2.SetPath([]uint32{10, 20})
	a3 := Attributes{}
	a3.SetPath([]uint32{30, 40, 50})
	want := []Attributes{a1, a2, a3}

	opts := []cmp.Option{
		cmpopts.EquateComparable(netip.Addr{}),
		cmpopts.IgnoreUnexported(Attributes{}),
	}
	for i, tc := range [][]Attributes{
		{a1, a3, a2},
		{a2, a1, a3},
		{a2, a3, a1},
		{a3, a1, a2},
		{a3, a2, a1},
	} {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			var as []unique.Handle[Attributes]
			for _, a := range tc {
				as = append(as, unique.Make(a))
			}
			sortAttributes(as)
			var got []Attributes
			for _, a := range as {
				got = append(got, a.Value())
			}
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("path mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
