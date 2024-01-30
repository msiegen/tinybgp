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

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	IPv4Unicast = RouteFamily(bgp.AFI_IP)<<16 | RouteFamily(bgp.SAFI_UNICAST)
	IPv6Unicast = RouteFamily(bgp.AFI_IP6)<<16 | RouteFamily(bgp.SAFI_UNICAST)
)

type RouteFamily uint32

func NewRouteFamily(afi uint16, safi uint8) RouteFamily {
	return RouteFamily(afi)<<16 | RouteFamily(safi)
}

func (a RouteFamily) Split() (uint16, uint8) {
	return uint16(a >> 16), uint8(a & 0xffff)
}

func RouteFamilyFor(a netip.Addr) RouteFamily {
	switch {
	case a.Is4():
		return IPv4Unicast
	case a.Is6():
		return IPv6Unicast
	default:
		return 0
	}
}
