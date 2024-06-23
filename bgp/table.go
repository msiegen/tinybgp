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
	"sync"
	"time"

	"golang.org/x/exp/maps"
)

// A Table is a set of networks that each have a distinct CIDR prefix.
type Table struct {
	mu              sync.Mutex
	networks        map[netip.Prefix]*Network
	networksVersion int64
	prefixes        []netip.Prefix
	prefixesVersion int64
}

// Network returns the network for the given prefix, creating an entry in the
// table if one does not already exist.
func (t *Table) Network(p netip.Prefix) *Network {
	t.mu.Lock()
	defer t.mu.Unlock()
	if n := t.networks[p]; n != nil {
		return n
	}
	if t.networks == nil {
		t.networks = map[netip.Prefix]*Network{}
	}
	n := &Network{}
	t.networks[p] = n
	t.networksVersion += 1
	return n
}

// Prefixes returns the prefixes of all the networks in the table.
func (t *Table) Prefixes() []netip.Prefix {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prefixesVersion != t.networksVersion {
		t.prefixes = maps.Keys(t.networks)
		t.prefixesVersion = t.networksVersion
	}
	return t.prefixes
}

// hasPrefix returns whether the prefix is in the table. It's an optimization
// for the FSM to avoid allocating a *Network for withdrawn prefixes that were
// never inserted in the first place (e.g. due to filters).
func (t *Table) hasPrefix(p netip.Prefix) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.networks[p]
	return ok
}

// Watch returns an iterator over all routes in the tables. The iterator yields
// every route once on startup, and then waits for changes and yields only the
// updated or withdrawn routes.
func Watch(t ...*Table) func(func(netip.Prefix, []Path) bool) {
	// TODO: Change return type to iter.Seq2[netip.Prefix, []Path] in Go 1.23.
	last := map[netip.Prefix]int64{}
	return func(yield func(netip.Prefix, []Path) bool) {
		for {
			for _, t := range t {
				t.mu.Lock()
				for p, n := range t.networks {
					t.mu.Unlock()
					bestPaths, version := n.BestPaths()
					if version != last[p] {
						last[p] = version
						if !yield(p, bestPaths) {
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
