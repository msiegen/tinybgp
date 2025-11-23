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
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	IPv4Unicast = Family(bgp.AFI_IP)<<16 | Family(bgp.SAFI_UNICAST)
	IPv6Unicast = Family(bgp.AFI_IP6)<<16 | Family(bgp.SAFI_UNICAST)
)

type Family uint32

func NewFamily(afi uint16, safi uint8) Family {
	return Family(afi)<<16 | Family(safi)
}

func (f Family) Split() (uint16, uint8) {
	return uint16(f >> 16), uint8(f & 0xffff)
}

func (f Family) String() string {
	afi, safi := f.Split()
	return fmt.Sprintf("%v:%v", afi, safi)
}

func FamilyFor(a netip.Addr) Family {
	switch {
	case a.Is4():
		return IPv4Unicast
	case a.Is6():
		return IPv6Unicast
	default:
		return 0
	}
}
