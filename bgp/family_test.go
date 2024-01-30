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
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func TestRouteFamily(t *testing.T) {
	for i, want := range []struct {
		AFI  uint16
		SAFI uint8
	}{
		{bgp.AFI_IP, bgp.SAFI_UNICAST},
		{bgp.AFI_IP6, bgp.SAFI_UNICAST},
		{bgp.AFI_IP, bgp.SAFI_MULTICAST},
		{bgp.AFI_IP6, bgp.SAFI_MULTICAST},
	} {
		a := NewRouteFamily(want.AFI, want.SAFI)
		gotAFI, gotSAFI := a.Split()
		if gotAFI != want.AFI {
			t.Errorf("%v: got AFI %v, want %v", i, gotAFI, want.AFI)
		}
		if gotSAFI != want.SAFI {
			t.Errorf("%v: got SAFI %v, want %v", i, gotSAFI, want.SAFI)
		}
	}
}

func TestRouteFamilyConstants(t *testing.T) {
	for i, c := range []struct {
		AFI  uint16
		SAFI uint8
		Want RouteFamily
	}{
		{bgp.AFI_IP, bgp.SAFI_UNICAST, IPv4Unicast},
		{bgp.AFI_IP6, bgp.SAFI_UNICAST, IPv6Unicast},
		{bgp.AFI_IP, bgp.SAFI_UNICAST, RouteFamily(bgp.RF_IPv4_UC)},
		{bgp.AFI_IP6, bgp.SAFI_UNICAST, RouteFamily(bgp.RF_IPv6_UC)},
	} {
		got := NewRouteFamily(c.AFI, c.SAFI)
		if got != c.Want {
			t.Errorf("%v: got %v, want %v", i, got, c.Want)
		}
	}
}
