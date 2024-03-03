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
