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
