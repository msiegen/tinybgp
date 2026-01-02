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
)

const (
	// initialAllPathsCapacity is the initial capacity of the slice that holds a
	// copy of a network's paths while iterating over routes. If the number of
	// paths to a network exceeds this, iteration will result in heap allocations.
	initialAllPathsCapacity = 64
	// editsBufferSize is the number of edits to a routing table that are tracked
	// to support incremental syncing. If the edits between two polling cycles
	// exceeds this, any watchers will have to iterate over the whole table to
	// resync.
	editsBufferSize = 1024
)

// edits holds a circular buffer of recent routing table edits.
type edits struct {
	edits [editsBufferSize]struct {
		nlri    netip.Prefix
		version int64
	}
	next int
}

// Mark records an edit if version differs from prior.
// It does nothing if the versions are the same.
func (e *edits) Mark(nlri netip.Prefix, version, prior int64) {
	if version == prior {
		return
	}
	e.edits[e.next].nlri = nlri
	e.edits[e.next].version = version
	e.next = (e.next + 1) % editsBufferSize
}

// ChangedSince populates the output slice with the NLRIs that have changed
// since the last version. The caller should provide an output slice of size
// editsBufferSize. The number of changed NLRIs is returned, along with a
// boolean whether the output is complete. If the output is incomplete, the
// caller should iterate over all networks in the table to catch up and then
// resume calling ChangedSince with a newer last version.
func (e *edits) ChangedSince(out []netip.Prefix, last int64) (int, bool) {
	next := e.next
	if e.edits[next].version > last {
		// We don't have enough history to enumerate the changes.
		return 0, false
	}
	limit := len(out)
	if limit > editsBufferSize {
		limit = editsBufferSize
	}
	var j int
	for i := 0; i < limit; i++ {
		if e.edits[next].version <= last {
			// Skip this edit... the caller already knows about it.
			next = (next + 1) % editsBufferSize
			continue
		}
		// Add this edit to the outputs.
		out[j] = e.edits[next].nlri
		j++
		next = (next + 1) % editsBufferSize
	}
	return j, true
}

// A Table is a set of networks that each have a distinct NLRI.
type Table struct {
	// Compare decides which attributes represent the better route.
	// If nil, the package level Compare function is used.
	Compare func(a, b Attributes) int

	version  atomic.Int64
	mu       sync.Mutex
	networks map[netip.Prefix]*network
	edits    edits
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
	n := t.network(nlri)
	prior := n.version
	n.addPath(t, a)
	t.edits.Mark(nlri, n.version, prior)
}

// RemovePath removes the path that goes via the specified peer.
// It is safe to call even if no path from the peer is present.
func (t *Table) RemovePath(nlri netip.Prefix, peer netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.network(nlri)
	prior := n.version
	n.removePath(t, peer)
	t.edits.Mark(nlri, n.version, prior)
}

// removePathsFrom removes all paths via the specified peer.
func (t *Table) removePathsFrom(peer netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for nlri, n := range t.networks {
		prior := n.version
		n.removePath(t, peer)
		t.edits.Mark(nlri, n.version, prior)
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
		ap := make([]attrHandle, 0, initialAllPathsCapacity)
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
			ap := make([]attrHandle, 0, initialAllPathsCapacity)
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
func (t *Table) bestRoutes() iter.Seq2[netip.Prefix, attrHandle] {
	return func(yield func(netip.Prefix, attrHandle) bool) {
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
func (t *Table) updatedRoutes(export Filter, tracked map[netip.Prefix]attrHandle, suppressed map[netip.Prefix]struct{}, version *int64, reevaluate bool) iter.Seq2[netip.Prefix, Attributes] {
	return func(yield func(netip.Prefix, Attributes) bool) {
		// announce yields an announcement, if the export filter allows it and an
		// identical route is not already tracked. It returns true if further
		// iteration is still needed.
		announce := func(nlri netip.Prefix, attrs attrHandle) bool {
			// Check if we previously yielded the same route.
			oldAttrs, isTracked := tracked[nlri]
			if !reevaluate && isTracked && attrs == oldAttrs {
				return true // Route is unchanged.
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
							return false
						}
					}
				}
				suppressed[nlri] = struct{}{}
				return true // Move on to the next route.
			}
			// The export filter allowed the route.
			delete(suppressed, nlri)
			if !yield(nlri, attrsValue) {
				return false
			}
			return true
		}

		// withdraw yields a withdrawal, if the route is no longer valid.
		// It returns true if further iteration is still needed.
		withdraw := func(nlri netip.Prefix) bool {
			if !t.hasNetwork(nlri) {
				if !yield(nlri, Attributes{}) {
					return false
				}
				delete(tracked, nlri)
				delete(suppressed, nlri)
			}
			return true
		}

		// Get a list of networks that have recently changed.
		t.mu.Lock()
		changed := make([]netip.Prefix, editsBufferSize)
		n, ok := t.edits.ChangedSince(changed, *version)
		current := t.version.Load()
		t.mu.Unlock()

		if ok {
			// We got a list of changes. Announce or withdraw the latest routes for
			// those networks. This may skip intermediate updates if a route changed
			// several times rapidly.
			for i := 0; i < n; i++ {
				nlri := changed[i]
				t.mu.Lock()
				attrs, ok := t.network(nlri).bestPath()
				t.mu.Unlock()
				if ok {
					// Announce new and updated routes.
					if !announce(nlri, attrs) {
						return
					}
				} else {
					// Withdraw removed routes.
					if _, ok := tracked[nlri]; ok {
						if !withdraw(nlri) {
							return
						}
					}
				}
			}
			*version = current
			return
		}

		// We did not get a complete list of changes, probably because the edits
		// buffer was overrun. Resync the entire table. This will cost some more
		// CPU locally, but it does not cause any extra network traffic as the
		// tracked and suppressed maps guard against duplicate announcements.
		*version = current
		// Announce new and updated routes.
		for nlri, attrs := range t.bestRoutes() {
			if !announce(nlri, attrs) {
				return
			}
		}
		// Withdraw removed routes.
		for nlri := range tracked {
			if !withdraw(nlri) {
				return
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
	tracked := make([]map[netip.Prefix]attrHandle, len(t))
	suppressed := make([]map[netip.Prefix]struct{}, len(t))
	for i := 0; i < len(t); i++ {
		tracked[i] = map[netip.Prefix]attrHandle{}
		suppressed[i] = map[netip.Prefix]struct{}{}
	}
	var version int64
	filter := func(nlri netip.Prefix, attrs *Attributes) error { return nil }
	return func(yield func(netip.Prefix, Attributes) bool) {
		for {
			for i, t := range t {
				for nlri, attrs := range t.updatedRoutes(filter, tracked[i], suppressed[i], &version, false) {
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
