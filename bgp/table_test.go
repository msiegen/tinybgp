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
	"net"
	"net/netip"
	"reflect"
	"slices"
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

	table.AddPath(nlri, Attributes{peer: peer})
	table.RemovePath(nlri, peer)
	table.AddPath(nlri, Attributes{peer: peer})

	var bestRoutesCount int
	for _, _ = range table.bestRoutes() {
		bestRoutesCount++
	}
	if bestRoutesCount != 1 {
		t.Errorf("got %v best routes, want 1", bestRoutesCount)
	}
}

func TestUpdatedRoutes(t *testing.T) {
	table := &Table{}
	peer1 := netip.MustParseAddr("3fff::1")
	peer2 := netip.MustParseAddr("3fff::2")
	a1 := Attributes{peer: peer1}
	a2 := Attributes{peer: peer2}
	prefix := func(i int) netip.Prefix {
		ip := net.ParseIP("2001:db8::")
		ip[12] = byte(i >> 24 & 0xf)
		ip[13] = byte(i >> 16 & 0xf)
		ip[14] = byte(i >> 8 & 0xf)
		ip[15] = byte(i & 0xf)
		addr, _ := netip.AddrFromSlice(ip)
		return netip.PrefixFrom(addr, 128)
	}

	exportFilter := func(nlri netip.Prefix, attrs Attributes) (Attributes, error) {
		if attrs.med == 999 {
			return Attributes{}, ErrDiscard
		}
		return attrs, nil
	}

	tracked := map[netip.Prefix]attrHandle{}
	suppressed := map[netip.Prefix]struct{}{}
	var version int64

	comparePrefixes := func(a, b netip.Prefix) int {
		return a.Addr().Compare(b.Addr())
	}
	collect := func() ([]netip.Prefix, []netip.Prefix) {
		var announce []netip.Prefix
		var withdraw []netip.Prefix
		for nlri, attrs := range table.updatedRoutes(exportFilter, tracked, suppressed, &version, false) {
			var zero Attributes
			if attrs == zero {
				withdraw = append(withdraw, nlri)
				continue
			}
			announce = append(announce, nlri)
		}
		slices.SortFunc(announce, comparePrefixes)
		slices.SortFunc(withdraw, comparePrefixes)
		return announce, withdraw
	}

	// Announce two routes.
	table.AddPath(prefix(0), a1)
	table.AddPath(prefix(1), a2)
	wantAnnounce := []netip.Prefix{prefix(0), prefix(1)}
	var wantWithdraw []netip.Prefix
	gotAnnounce, gotWithdraw := collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Do not yield the same routes again.
	wantAnnounce = nil
	wantWithdraw = nil
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Announce a new route.
	table.AddPath(prefix(2), a1)
	wantAnnounce = []netip.Prefix{prefix(2)}
	wantWithdraw = nil
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Update an existing route.
	a1m := a1
	a1m.SetMED(10) // arbitrary modification
	table.AddPath(prefix(0), a1m)
	wantAnnounce = []netip.Prefix{prefix(0)}
	wantWithdraw = nil
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Withdraw a route.
	table.RemovePath(prefix(0), peer1)
	wantAnnounce = nil
	wantWithdraw = []netip.Prefix{prefix(0)}
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Withdraw everything from a particular peer.
	table.removePathsFrom(peer2)
	wantAnnounce = nil
	wantWithdraw = []netip.Prefix{prefix(1)}
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Announce one route, withdraw another, and then immeidately overrun
	// the edits buffer with a bunch of transient updates.
	table.AddPath(prefix(3), a1)
	table.RemovePath(prefix(2), peer1)
	for i := 0; i < editsBufferSize+10; i++ {
		table.AddPath(prefix(i+65536), a1)
	}
	for i := 0; i < editsBufferSize+10; i++ {
		table.RemovePath(prefix(i+65536), peer1)
	}
	wantAnnounce = []netip.Prefix{prefix(3)}
	wantWithdraw = []netip.Prefix{prefix(2)}
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Update the same route twice.
	a1m = a1
	a1m.SetMED(20) // arbitrary modification
	table.AddPath(prefix(3), a1m)
	a1m.SetMED(30) // arbitrary modification
	table.AddPath(prefix(3), a1m)
	wantAnnounce = []netip.Prefix{prefix(3)}
	wantWithdraw = nil
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Update a route in a way that gets rejected by the export filter.
	a1m.SetMED(999) // not allowed to be exporter
	table.AddPath(prefix(3), a1m)
	wantAnnounce = nil
	wantWithdraw = []netip.Prefix{prefix(3)}
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}

	// Revert the previous update to allow export again.
	a1m.ClearMED() // allowed to be exported
	table.AddPath(prefix(3), a1m)
	wantAnnounce = []netip.Prefix{prefix(3)}
	wantWithdraw = nil
	gotAnnounce, gotWithdraw = collect()
	if !reflect.DeepEqual(gotAnnounce, wantAnnounce) {
		t.Errorf("got announce %v, want %v", gotAnnounce, wantAnnounce)
	}
	if !reflect.DeepEqual(gotWithdraw, wantWithdraw) {
		t.Errorf("got withdraw %v, want %v", gotWithdraw, wantWithdraw)
	}
}

func TestWatchBest(t *testing.T) {
	table := &Table{}
	p1 := netip.MustParsePrefix("2001:db8:1::/48")
	nh1 := netip.MustParseAddr("2001:db8:100::1")
	a1 := Attributes{
		peer:    nh1,
		nexthop: nh1,
	}
	p2 := netip.MustParsePrefix("2001:db8:2::/48")
	nh2a := netip.MustParseAddr("2001:db8:100::2a")
	a2a := Attributes{
		peer:    nh2a,
		nexthop: nh2a,
		path:    serializePath([]uint32{64512, 64513}),
	}
	nh2b := netip.MustParseAddr("2001:db8:100::2b")
	a2b := Attributes{
		peer:    nh2b,
		nexthop: nh2b,
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
