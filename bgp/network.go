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
	"unique"
)

// initialBestPathsCapacity is the initial capacity of the slice that holds a
// copy of the old best paths during a mutation. If the number of best paths
// exceeds this, the temporary copy will escape to the heap.
const initialBestPathsCapacity = 16

// A network represents a range of addresses with a common prefix that can be
// reached by zero or more distinct paths.
type network struct {
	paths        []attrHandle
	version      int64
	numBestPaths int
}

// addPath adds a path by which this network can be reached.
// It replaces any previously added path from the same peer.
func (n *network) addPath(table *Table, a Attributes) {
	bestPaths := make([]attrHandle, 0, initialBestPathsCapacity)
	ah := unique.Make(a)
	for i, old := range n.paths {
		if ah == old {
			// Path is unchanged. No replacement needed.
			return
		}
		if old.Value().Peer() == a.Peer() {
			// We previously got a path from this same peer. Replace it.
			bestPaths = append(bestPaths, n.paths[:n.numBestPaths]...)
			n.paths[i] = ah
			n.sortPaths(table, bestPaths)
			return
		}
	}
	// First time we've seen this path. Add it.
	bestPaths = append(bestPaths, n.paths[:n.numBestPaths]...)
	n.paths = append(n.paths, ah)
	n.sortPaths(table, bestPaths)
}

// removePath removes the path via the specified peer.
// It is safe to call even if no path from the peer is present.
func (n *network) removePath(table *Table, peer netip.Addr) {
	bestPaths := make([]attrHandle, 0, initialBestPathsCapacity)
	bestPaths = append(bestPaths, n.paths[:n.numBestPaths]...)
	paths := slices.DeleteFunc(n.paths, func(old attrHandle) bool {
		return old.Value().Peer() == peer
	})
	if len(paths) == len(n.paths) {
		// No path was removed. This is fine.
		return
	}
	// A path was removed.
	n.paths = paths
	n.sortPaths(table, bestPaths)
}

// countBestPaths counts the number of paths that are tied for best path.
func countBestPaths(paths []attrHandle, cmp func(a, b Attributes) int) int {
	for i := 1; i < len(paths); i++ {
		a := paths[i-1].Value()
		b := paths[i].Value()
		if cmp(a, b) != 0 {
			return i
		}
	}
	return len(paths)
}

// sortPaths sorts n.paths. It should be passed a copy of the previous best
// paths. If the new best paths after sorting differ from the provided ones,
// n.numBestPaths and n.version will be updated.
func (n *network) sortPaths(table *Table, bestPaths []attrHandle) {
	cmp := table.Compare
	if cmp == nil {
		cmp = Compare
	}
	sortAttributes(n.paths, cmp)
	numBestPaths := countBestPaths(n.paths, cmp)
	if slices.Equal(bestPaths, n.paths[:numBestPaths]) {
		// The best paths have not changed.
		return
	}
	// One of the best paths has changed.
	n.numBestPaths = numBestPaths
	n.version = table.version.Add(1)
}

var (
	zeroAttributes = unique.Make(Attributes{})
)

// bestPath returns the best path to the network, or false if no path exists.
func (n *network) bestPath() (attrHandle, bool) {
	if n == nil || len(n.paths) == 0 {
		return zeroAttributes, false
	}
	return n.paths[0], true
}

// bestMultiPath returns potentially multiple best paths to the network. It
// also returns a generation number, which may be passed on subsequent calls to
// skip the return in case the best paths haven't changed. It returns a boolean
// to indicate whether a new set of routes were returned (including the empty
// set, which indicates a withdraw).
func (n *network) bestMultiPath(generation int64) ([]attrHandle, int64, bool) {
	if n.version == generation {
		return nil, n.version, false
	}
	if n.numBestPaths == 0 {
		return nil, n.version, true
	}
	return slices.Clone(n.paths[:n.numBestPaths]), n.version, true
}

// hasPath returns whether at least one path is present.
func (n *network) hasPath() bool {
	return n != nil && len(n.paths) != 0
}
