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
	"sync"

	"golang.org/x/exp/slices"
)

type Network struct {
	mu               sync.Mutex
	allPaths         []Path
	allPathsVersion  int64
	bestPaths        []Path
	bestPathsVersion int64
	generation       int64
}

func (n *Network) AddPath(p Path) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.allPaths = append(n.allPaths, p)
	n.allPathsVersion += 1
}

func (n *Network) RemovePath(p Path) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, item := range n.allPaths {
		if item.Equal(p) {
			s := slices.Delete(n.allPaths, i, i+1)
			n.allPaths[len(s)] = Path{} // for garbage collection
			n.allPaths = s
			break
		}
	}
	if len(n.allPaths) == 0 {
		n.allPaths = nil
	}
	n.allPathsVersion += 1
}

func (n *Network) BestPaths() ([]Path, int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.bestPathsVersion != n.allPathsVersion {
		if len(n.allPaths) == 0 {
			n.bestPaths = nil
			n.generation += 1
		} else {
			SortPaths(n.allPaths)
			// TODO: If there are multiple shortest paths, return them all for ECMP.
			// Will need to make sure that a change to the *number* of best paths
			// causes the generation to increment.
			if len(n.bestPaths) == 0 || !n.bestPaths[0].Equal(n.allPaths[0]) {
				n.generation += 1
			}
			n.bestPaths = n.allPaths[:1]
		}
		n.bestPathsVersion = n.allPathsVersion
	}
	return n.bestPaths, n.generation
}
