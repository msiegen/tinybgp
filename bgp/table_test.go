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
	"net/netip"
	"testing"
)

func TestTable(t *testing.T) {
	table := &Table{}

	p1 := netip.MustParsePrefix("2001:db8:1::/48")
	p2 := netip.MustParsePrefix("2001:db8:2::/48")

	n1 := table.Network(p1)
	n2 := table.Network(p2)
	n3 := table.Network(p1)

	if got, want := len(table.Prefixes()), 2; got != want {
		t.Errorf("got %v prefixes, want %v", got, want)
	}

	if n1 == n2 {
		t.Error("n1 == n2, want different networks")
	}

	if n1 != n3 {
		t.Error("n1 != n3, want the same network")
	}

	p4 := netip.MustParsePrefix("2001:db8:4::/48")
	table.Network(p4)

	if got, want := len(table.Prefixes()), 3; got != want {
		t.Errorf("got %v prefixes, want %v", got, want)
	}
}
