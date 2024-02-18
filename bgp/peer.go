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
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// A Filter modifies a path upon import or export. Filters may return ErrDiscard
// to deny propagation of the path.
type Filter func(netip.Prefix, Path) (Path, error)

// ErrDiscard is returned by filters that have made an explicit decision to
// discard a path.
var ErrDiscard = errors.New("discard")

type Peer struct {
	ASN                   uint32
	LocalAddr, RemoteAddr netip.Addr
	Port                  int
	Passive               bool
	// If DialerControl is not nil, it is called after creating the network
	// connection but before actually dialing. See
	// https://pkg.go.dev/net#Dialer.Control for details.
	DialerControl func(_, _ string, _ syscall.RawConn) error
	ImportFilter  Filter
	ExportFilter  Filter
	Timers        *Timers
	fsm           *fsm
	dynamic       bool
}

func (p *Peer) localAddr() net.Addr {
	if !p.LocalAddr.IsValid() {
		return nil
	}
	return &net.TCPAddr{
		IP:   net.IP(p.LocalAddr.AsSlice()),
		Zone: p.LocalAddr.Zone(),
	}
}

func (p *Peer) addr() string {
	port := 179
	if p.Port != 0 {
		port = p.Port
	}
	if p.RemoteAddr.Is6() {
		return "[" + p.RemoteAddr.String() + "]:" + strconv.Itoa(port)
	}
	return p.RemoteAddr.String() + ":" + strconv.Itoa(port)
}

func (p *Peer) transportAFI() uint16 {
	for _, a := range []netip.Addr{p.LocalAddr, p.RemoteAddr} {
		switch {
		case a.Is4():
			return bgp.AFI_IP
		case a.Is6():
			return bgp.AFI_IP6
		}
	}
	return 0
}

func (p *Peer) start(s *Server) {
	if p.fsm != nil {
		p.fsm.server.fatalf("tried to start the same peer twice")
	}
	p.fsm = &fsm{
		server:       s,
		timers:       newTimers(p.Timers),
		exportFilter: p.ExportFilter,
		acceptC:      make(chan net.Conn, 1),
		stopC:        make(chan struct{}),
		doneC:        make(chan struct{}),
	}
	go p.fsm.run(p)
}

func (p *Peer) stop() {
	p.fsm.stop()
}
