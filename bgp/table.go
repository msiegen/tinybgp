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
	"iter"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unique"
)

// initialAllPathsCapacity is the initial capacity of the slice that holds a
// copy of a network's paths while iterating over routes. If the number of
// paths to a network exceeds this, iteration will result in heap allocations.
const initialAllPathsCapacity = 64

// A Table is a set of networks that each have a distinct NLRI.
type Table struct {
	// Compare decides which attributes represent the better route.
	// If nil, the package level Compare function is used.
	Compare func(a, b *Attributes) int

	version  atomic.Int64
	mu       sync.Mutex
	networks map[netip.Prefix]*network
}

// network returns a single network. The first time it's called for a given
// NLRI, it creates an entry in the table with no paths.
func (t *Table) network(nlri netip.Prefix) *network {
	if n := t.networks[nlri]; n != nil {
		return n
	}
	if t.networks == nil {
		t.networks = map[netip.Prefix]*network{}
	}
	n := &network{}
	t.networks[nlri] = n
	return n
}

// hasNetwork returns whether the NLRI is in the table. It's an optimization
// for the FSM to avoid allocating a *Network when processing a withdraw for a
// route that was never inserted due to import filters.
func (t *Table) hasNetwork(nlri netip.Prefix) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ok := t.networks[nlri]
	if !ok {
		return false
	}
	return n.hasPath()
}

// AddPath adds a path to the given network.
// It replaces any previously added path from the same peer.
func (t *Table) AddPath(nlri netip.Prefix, a Attributes) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.network(nlri).addPath(t, a)
}

// RemovePath removes the path that goes via the specified peer.
// It is safe to call even if no path from the peer is present.
func (t *Table) RemovePath(nlri netip.Prefix, peer netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.network(nlri).removePath(t, peer)
}

// removePathsFrom removes all paths via the specified peer.
func (t *Table) removePathsFrom(peer netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, n := range t.networks {
		n.removePath(t, peer)
	}
}

// Routes returns an iterator that yields all the routes for one network.
func (t *Table) Routes(nlri netip.Prefix) iter.Seq[Attributes] {
	return func(yield func(Attributes) bool) {
		t.mu.Lock()
		n, ok := t.networks[nlri]
		if !ok {
			t.mu.Unlock()
			return
		}
		ap := make([]unique.Handle[Attributes], 0, initialAllPathsCapacity)
		ap = append(ap, n.paths...)
		t.mu.Unlock()
		for _, attrs := range ap {
			if !yield(attrs.Value()) {
				return
			}
		}
	}
}

// AllRoutes returns an iterator that yields all the routes for every network.
func (t *Table) AllRoutes() iter.Seq2[netip.Prefix, Attributes] {
	return func(yield func(netip.Prefix, Attributes) bool) {
		t.mu.Lock()
		for p, n := range t.networks {
			ap := make([]unique.Handle[Attributes], 0, initialAllPathsCapacity)
			ap = append(ap, n.paths...)
			t.mu.Unlock()
			for _, attrs := range ap {
				if !yield(p, attrs.Value()) {
					return
				}
			}
			t.mu.Lock()
		}
		t.mu.Unlock()
	}
}

// bestRoutes returns an iterator that yields the best route for each network.
func (t *Table) bestRoutes() iter.Seq2[netip.Prefix, unique.Handle[Attributes]] {
	return func(yield func(netip.Prefix, unique.Handle[Attributes]) bool) {
		t.mu.Lock()
		for p, n := range t.networks {
			attrs, ok := n.bestPath()
			t.mu.Unlock()
			if ok {
				if !yield(p, attrs) {
					return
				}
			}
			t.mu.Lock()
		}
		t.mu.Unlock()
	}
}

// updatedRoutes returns an iterator that yields only the routes that changed
// since the last call. State is tracked across calls through the tracked and
// suppressed maps.
func (t *Table) updatedRoutes(export Filter, tracked map[netip.Prefix]unique.Handle[Attributes], suppressed map[netip.Prefix]struct{}, reevaluate bool) iter.Seq2[netip.Prefix, Attributes] {
	return func(yield func(netip.Prefix, Attributes) bool) {
		// Announce new and updated routes.
		for nlri, attrs := range t.bestRoutes() {
			// Check if we previously yielded the same route.
			oldAttrs, isTracked := tracked[nlri]
			if !reevaluate && isTracked && attrs == oldAttrs {
				continue // Route is unchanged.
			}
			// We did not previously yield this route. Decide whether we should,
			// and cache the decision for later reuse.
			tracked[nlri] = attrs
			attrsValue := attrs.Value()
			if err := export(nlri, &attrsValue); err != nil {
				// The export filter rejected the route.
				if isTracked {
					if _, ok := suppressed[nlri]; !ok {
						// We previously yielded a route for this NLRI, so need to withdraw.
						if !yield(nlri, Attributes{}) {
							return
						}
					}
				}
				suppressed[nlri] = struct{}{}
				continue // Move on to the next route.
			}
			// The export filter allowed the route.
			delete(suppressed, nlri)
			if !yield(nlri, attrsValue) {
				return
			}
		}
		// Withdraw removed routes.
		for nlri := range tracked {
			if !t.hasNetwork(nlri) {
				if !yield(nlri, Attributes{}) {
					return
				}
				delete(tracked, nlri)
				delete(suppressed, nlri)
			}
		}
	}
}

// WatchBest returns an infinite iterator that yields the best route for each
// network in each table. The disappearance of a route is signaled with a zero
// value Attributes.
func WatchBest(t ...*Table) iter.Seq2[netip.Prefix, Attributes] {
	if len(t) == 0 {
		return nil
	}
	tracked := make([]map[netip.Prefix]unique.Handle[Attributes], len(t))
	suppressed := make([]map[netip.Prefix]struct{}, len(t))
	for i := 0; i < len(t); i++ {
		tracked[i] = map[netip.Prefix]unique.Handle[Attributes]{}
		suppressed[i] = map[netip.Prefix]struct{}{}
	}
	filter := func(nlri netip.Prefix, attrs *Attributes) error { return nil }
	return func(yield func(netip.Prefix, Attributes) bool) {
		for {
			for i, t := range t {
				for nlri, attrs := range t.updatedRoutes(filter, tracked[i], suppressed[i], false) {
					if !yield(nlri, attrs) {
						return
					}
				}
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// WatchBestMultiPath returns an infinite iterator that yields the best
// multipath routes for each network in each table. A multipath route is
// comprised of a set of routes on which the Compare function returns zero.
// The disappearance of a route is signaled with an empty slice of Attributes.
func WatchBestMultiPath(t ...*Table) iter.Seq2[netip.Prefix, []Attributes] {
	if len(t) == 0 {
		return nil
	}
	versions := make([]map[netip.Prefix]int64, len(t))
	for i := 0; i < len(t); i++ {
		versions[i] = map[netip.Prefix]int64{}
	}
	return func(yield func(netip.Prefix, []Attributes) bool) {
		for {
			for i, t := range t {
				t.mu.Lock()
				for nlri, n := range t.networks {
					ahs, version, ok := n.bestMultiPath(versions[i][nlri])
					t.mu.Unlock()
					if ok {
						versions[i][nlri] = version
						var attrss []Attributes
						if len(ahs) != 0 {
							attrss = make([]Attributes, len(ahs))
							for i, ah := range ahs {
								attrss[i] = ah.Value()
							}
						}
						if !yield(nlri, attrss) {
							return
						}
					}
					t.mu.Lock()
				}
				t.mu.Unlock()
			}
			time.Sleep(1 * time.Second)
		}
	}
}
