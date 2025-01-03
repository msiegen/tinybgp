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
	"net"
	"net/netip"
)

// addrFromNetAddr extracts the IP and port from a *net.TCPAddr.
func addrFromNetAddr(addr net.Addr) (netip.Addr, int) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		aa, _ := netip.AddrFromSlice(a.IP)
		return aa.WithZone(a.Zone), a.Port
	default:
		return netip.Addr{}, 0
	}
}
