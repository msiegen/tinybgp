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
)

// A Network represents a range of addresses with a common prefix that can be
// reached by zero or more distinct paths.
type Network struct {
	version      *atomic.Int64
	mu           sync.Mutex
	paths        []Attributes
	pathsVersion int64
	sorted       bool
}

// AddPath adds a path by which this network can be reached.
// It replaces any previously added path from the same peer.
func (n *Network) AddPath(a Attributes) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, old := range n.paths {
		if old.Peer == a.Peer {
			// We previously got a path from this same peer. Replace it.
			if a == old {
				// Path is unchanged. No replacement needed.
				return
			}
			n.paths[i] = a
			n.pathsVersion = n.version.Add(1)
			n.sorted = false
			return
		}
	}
	// First time we've seen this path. Add it.
	n.paths = append(n.paths, a)
	n.pathsVersion = n.version.Add(1)
	n.sorted = false
}

// RemovePath removes the path via the specified peer.
// It is safe to call even if no path from the peer is present.
func (n *Network) RemovePath(peer netip.Addr) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.paths = slices.DeleteFunc(n.paths, func(old Attributes) bool {
		return old.Peer == peer
	})
}

// bestPath returns the best path to the network, or false if no path exists.
func (n *Network) bestPath() (Attributes, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.paths) == 0 {
		return Attributes{}, false
	}
	if !n.sorted {
		sortAttributes(n.paths)
		n.sorted = true
	}
	return n.paths[0], true
}

// hasPath returns whether at least one path is present.
func (n *Network) hasPath() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.paths) != 0
}
