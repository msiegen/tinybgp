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
	"net/netip"
	"testing"
)

func TestNetworkPaths(t *testing.T) {
	n := &network{}
	p1 := netip.MustParseAddr("2001:db8::1")
	a1 := Attributes{
		Peer:    p1,
		Nexthop: p1,
		path:    serializePath([]uint32{64512}),
	}
	p2 := netip.MustParseAddr("2001:db8::2")
	a2 := Attributes{
		Peer:    p2,
		Nexthop: p2,
		path:    serializePath([]uint32{64512, 64522}),
	}
	if n.hasPath() {
		t.Errorf("hasPath returned %v, want %v", true, false)
	}
	table := &Table{}
	if _, ok := n.bestPath(); ok {
		t.Errorf("bestPath returned ok %v, want %v", true, false)
	}
	n.addPath(table, a2)
	if !n.hasPath() {
		t.Errorf("hasPath returned %v, want %v", false, true)
	}
	if best, ok := n.bestPath(); !ok {
		t.Errorf("bestPath returned ok %v, want %v", false, true)
	} else if best.Value() != a2 {
		t.Errorf("bestPath returned %v, want %v", best.Value(), a2)
	}
	n.addPath(table, a1)
	if best, ok := n.bestPath(); !ok {
		t.Errorf("bestPath returned ok %v, want %v", false, true)
	} else if best.Value() != a1 {
		t.Errorf("bestPath returned %v, want %v", best.Value(), a1)
	}
	n.removePath(table, p1)
	if best, ok := n.bestPath(); !ok {
		t.Errorf("bestPath returned ok %v, want %v", false, true)
	} else if best.Value() != a2 {
		t.Errorf("bestPath returned %v, want %v", best.Value(), a2)
	}
	n.removePath(table, p2)
	if _, ok := n.bestPath(); ok {
		t.Errorf("bestPath returned ok %v, want %v", true, false)
	}
	if n.hasPath() {
		t.Errorf("hasPath returned %v, want %v", true, false)
	}
}
