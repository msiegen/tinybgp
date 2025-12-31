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
	"time"
)

func TestTable(t *testing.T) {
	table := &Table{}

	p1 := netip.MustParsePrefix("2001:db8:1::/48")
	p2 := netip.MustParsePrefix("2001:db8:2::/48")

	n1 := table.network(p1)
	n2 := table.network(p2)
	n3 := table.network(p1)

	if got, want := len(table.networks), 2; got != want {
		t.Errorf("got %v prefixes, want %v", got, want)
	}

	if n1 == n2 {
		t.Error("n1 == n2, want different networks")
	}

	if n1 != n3 {
		t.Error("n1 != n3, want the same network")
	}

	p4 := netip.MustParsePrefix("2001:db8:4::/48")
	table.network(p4)

	if got, want := len(table.networks), 3; got != want {
		t.Errorf("got %v prefixes, want %v", got, want)
	}

	for _, want := range []netip.Prefix{p1, p2, p4} {
		if table.hasNetwork(want) {
			t.Errorf("hasNetwork(%v) returned %v, want %v", want, false, true)
		}
	}

	table.AddPath(p1, Attributes{})
	table.AddPath(p2, Attributes{})
	table.AddPath(p1, Attributes{})

	for _, want := range []netip.Prefix{p1, p2} {
		if !table.hasNetwork(want) {
			t.Errorf("hasNetwork(%v) returned %v, want %v", want, true, false)
		}
	}

	var networksCount int
	for _, n := range table.networks {
		if n.hasPath() {
			networksCount++
		}
	}
	if networksCount != 2 {
		t.Errorf("got %v networks, want 2", networksCount)
	}

	var bestRoutesCount int
	for _, _ = range table.bestRoutes() {
		bestRoutesCount++
	}
	if bestRoutesCount != 2 {
		t.Errorf("got %v best routes, want 2", bestRoutesCount)
	}
}

func TestTableAddRemove(t *testing.T) {
	table := &Table{}

	nlri := netip.MustParsePrefix("2001:db8:1::/48")
	peer := netip.MustParseAddr("3fff::1")

	table.AddPath(nlri, Attributes{Peer: peer})
	table.RemovePath(nlri, peer)
	table.AddPath(nlri, Attributes{Peer: peer})

	var bestRoutesCount int
	for _, _ = range table.bestRoutes() {
		bestRoutesCount++
	}
	if bestRoutesCount != 1 {
		t.Errorf("got %v best routes, want 1", bestRoutesCount)
	}
}

func TestWatchBest(t *testing.T) {
	table := &Table{}
	p1 := netip.MustParsePrefix("2001:db8:1::/48")
	nh1 := netip.MustParseAddr("2001:db8:100::1")
	a1 := Attributes{
		Peer:    nh1,
		Nexthop: nh1,
	}
	p2 := netip.MustParsePrefix("2001:db8:2::/48")
	nh2a := netip.MustParseAddr("2001:db8:100::2a")
	a2a := Attributes{
		Peer:    nh2a,
		Nexthop: nh2a,
		path:    serializePath([]uint32{64512, 64513}),
	}
	nh2b := netip.MustParseAddr("2001:db8:100::2b")
	a2b := Attributes{
		Peer:    nh2b,
		Nexthop: nh2b,
		path:    serializePath([]uint32{64512}),
	}

	// Announce prefix 1
	table.AddPath(p1, a1)
	steps := []struct {
		wantNLRI  netip.Prefix
		wantAttrs Attributes
		op        func(netip.Prefix, Attributes)
	}{
		{
			// Watch for route 1
			wantNLRI:  p1,
			wantAttrs: a1,
			// Announce route 2 with path length 2
			op: func(nlri netip.Prefix, attrs Attributes) {
				table.AddPath(p2, a2a)
			},
		},
		{
			// Watch for route 2 with path length 2
			wantNLRI:  p2,
			wantAttrs: a2a,
			// Announce route 2 with path length 1
			op: func(nlri netip.Prefix, attrs Attributes) {
				table.AddPath(p2, a2b)
			},
		},
		{
			// Watch for route 2 with path length 1
			wantNLRI:  p2,
			wantAttrs: a2b,
			// Withdraw route 1
			op: func(nlri netip.Prefix, attrs Attributes) {
				table.RemovePath(p1, nh1)
			},
		},
		{
			// Watch for disappearance of route 1
			wantNLRI:  p1,
			wantAttrs: Attributes{},
			// Withdraw route 2 with path length 1
			op: func(nlri netip.Prefix, attrs Attributes) {
				table.RemovePath(p2, nh2b)
			},
		},
		{
			// Watch for route 2 with path length 2
			wantNLRI:  p2,
			wantAttrs: a2a,
		},
	}

	type route struct {
		nlri  netip.Prefix
		attrs Attributes
	}
	c := make(chan route, 1)
	go func() {
		for nlri, attrs := range WatchBest(table) {
			c <- route{nlri, attrs}
		}
	}()
	next := func() (netip.Prefix, Attributes, bool) {
		select {
		case r := <-c:
			return r.nlri, r.attrs, true
		case <-time.After(5 * time.Second):
			return netip.Prefix{}, Attributes{}, false
		}
	}
	for i, s := range steps {
		nlri, attrs, ok := next()
		if !ok {
			t.Fatalf("timed out at step %v", i)
		}
		if nlri != s.wantNLRI {
			t.Errorf("step %v: got NLRI %v, want %v", i, nlri, s.wantNLRI)
		}
		if attrs != s.wantAttrs {
			t.Errorf("step %v: got attrs %v, want %v", i, attrs, s.wantAttrs)
		}
		if s.op != nil {
			s.op(nlri, attrs)
		}
	}
}
