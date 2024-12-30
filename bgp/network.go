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
	"slices"
	"sync"
	"sync/atomic"
	"unique"
)

// A Network represents a range of addresses with a common prefix that can be
// reached by zero or more distinct paths.
type Network struct {
	version          *atomic.Int64 // shared counter for all networks in the table
	mu               sync.Mutex
	paths            []unique.Handle[Attributes]
	pathsVersion     int64
	bestPaths        []unique.Handle[Attributes]
	bestPathsVersion int64
	sorted           bool
}

// AddPath adds a path by which this network can be reached.
// It replaces any previously added path from the same peer.
func (n *Network) AddPath(a Attributes) {
	ah := unique.Make(a)
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, old := range n.paths {
		if ah == old {
			// Path is unchanged. No replacement needed.
			return
		}
		if old.Value().Peer == a.Peer {
			// We previously got a path from this same peer. Replace it.
			n.paths[i] = ah
			n.pathsVersion = n.version.Add(1)
			n.sorted = false
			return
		}
	}
	// First time we've seen this path. Add it.
	n.paths = append(n.paths, ah)
	n.pathsVersion = n.version.Add(1)
	n.sorted = false
}

// RemovePath removes the path via the specified peer.
// It is safe to call even if no path from the peer is present.
func (n *Network) RemovePath(peer netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	paths := slices.DeleteFunc(n.paths, func(old unique.Handle[Attributes]) bool {
		return old.Value().Peer == peer
	})
	if len(paths) != len(n.paths) {
		n.pathsVersion = n.version.Add(1)
		n.sorted = false
	}
	n.paths = paths
}

// countBestPaths counts the number of paths that are tied for best path.
func countBestPaths(paths []unique.Handle[Attributes], cmp func(a, b *Attributes) int) int {
	if cmp == nil {
		cmp = Compare
	}
	for i := 1; i < len(paths); i++ {
		a := paths[i-1].Value()
		b := paths[i].Value()
		if cmp(&a, &b) != 0 {
			return i
		}
	}
	return len(paths)
}

// sortPaths ensures that n.paths is sorted and that
// n.bestPaths contains the best paths.
func (n *Network) sortPaths(t *Table) {
	cmp := t.Compare
	if cmp == nil {
		cmp = Compare
	}
	sortAttributes(n.paths, cmp)
	numBestPaths := countBestPaths(n.paths, cmp)
	if numBestPaths != len(n.bestPaths) {
		// The number of best paths has changed.
		n.bestPaths = n.bestPaths[:0]
		n.bestPaths = append(n.bestPaths, n.paths[:numBestPaths]...)
		n.bestPathsVersion = n.pathsVersion
		n.sorted = true
		return
	}
	if !slices.Equal(n.bestPaths, n.paths[:numBestPaths]) {
		// One of the best paths has changed.
		copy(n.bestPaths, n.paths[:numBestPaths])
		n.bestPathsVersion = n.pathsVersion
		n.sorted = true
		return
	}
	// The best paths have not changed.
	n.sorted = true
}

// allPaths returns a copy of all paths to the network.
func (n *Network) allPaths(t *Table) []unique.Handle[Attributes] {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.paths) == 0 {
		return nil
	}
	if !n.sorted {
		n.sortPaths(t)
	}
	return slices.Clone(n.paths)
}

var (
	zeroAttributes = unique.Make(Attributes{})
)

// bestPath returns the best path to the network, or false if no path exists.
func (n *Network) bestPath(t *Table) (unique.Handle[Attributes], bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.paths) == 0 {
		return zeroAttributes, false
	}
	if !n.sorted {
		n.sortPaths(t)
	}
	return n.paths[0], true
}

// bestMultiPath returns potentially multiple best paths to the network. It
// also returns a generation number, which may be passed on subsequent calls to
// skip the return in case the best paths haven't changed. It returns a boolean
// to indicate whether a new set of routes were returned (including the empty
// set, which indicates a withdraw).
func (n *Network) bestMultiPath(t *Table, generation int64) ([]unique.Handle[Attributes], int64, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.sorted {
		n.sortPaths(t)
	}
	if n.bestPathsVersion == generation {
		return nil, n.bestPathsVersion, false
	}
	return slices.Clone(n.bestPaths), n.bestPathsVersion, true
}

// hasPath returns whether at least one path is present.
func (n *Network) hasPath() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.paths) != 0
}
