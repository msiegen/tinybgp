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

	"golang.org/x/exp/slices"
)

// A Network represents a range of addresses with a common prefix that can be
// reached by zero or more distinct paths.
type Network struct {
	mu               sync.Mutex
	allPaths         []Path
	allPathsVersion  int64
	bestPaths        []Path
	bestPathsVersion int64
	generation       int64
}

// AddPath adds a path by which this network can be reached. It replaces any
// previously added path from the same peer.
func (n *Network) AddPath(p Path) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.allPathsVersion += 1
	for i, oldPath := range n.allPaths {
		if oldPath.Peer == p.Peer {
			n.allPaths[i] = p
			return
		}
	}
	n.allPaths = append(n.allPaths, p)
}

// RemovePath removes a path via the specified peer. It is safe to call even if
// no path from the peer is present.
func (n *Network) RemovePath(peer netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, item := range n.allPaths {
		if item.Peer == peer {
			s := slices.Delete(n.allPaths, i, i+1)
			n.allPaths[len(s)] = Path{} // for garbage collection
			n.allPaths = s
			if len(n.allPaths) == 0 {
				n.allPaths = nil
			}
			n.allPathsVersion += 1
			return
		}
	}
}

// BestPaths returns the best way to reach this network, and a generation number
// that increments any time the best path has changed. An empty slice is
// returned if no path is known, and multiple paths may be returned if several
// are equally good.
func (n *Network) BestPaths() ([]Path, int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bestPathsVersion != n.allPathsVersion {
		if len(n.allPaths) == 0 {
			n.bestPaths = nil
			n.generation += 1
		} else {
			SortPaths(n.allPaths)
			n.generation += 1
			// TODO: If there are multiple shortest paths, return them all for ECMP.
			n.bestPaths = n.allPaths[:1]
		}
		n.bestPathsVersion = n.allPathsVersion
	}
	return n.bestPaths, n.generation
}
