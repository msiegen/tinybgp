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

// A Filter is a function that runs upon import or export of a path.
//
// Import filters always receive a new instance of a Path and may safely modify
// it to apply local policy. Export filters receive a shallow copy of the Path
// from the local table and may modify the values in it, but are responsible for
// deep copying any reference types that they wish to modify themselves.
//
// A filter may return ErrDiscard to terminate the evaluation of the filter
// chain and prevent the path from being imported or exported.
type Filter func(prefix netip.Prefix, p *Path) error

// ErrDiscard is returned by filters that have made an explicit decision to
// discard a path.
var ErrDiscard = errors.New("discard")

// A Peer is a BGP neighbor.
type Peer struct {
	// Addr is the address of the peer. This is required.
	Addr netip.Addr
	// Port is the port on which the peer listens.
	// If not set, port 179 is assumed.
	Port int
	// Passive inhibits dialing the peer. The local server will still listen for
	// incomming connections from the peer.
	Passive bool

	// LocalAddr is the local address.
	LocalAddr netip.Addr

	// ASN is the expected ASN of the peer.
	// If present, it will be verified upon connection establishment.
	ASN uint32

	// Import stores the network reachability information received from the peer.
	//
	// You must initialize this to contain a non-nil table for each route family
	// that you want to accept from the peer, prior to adding the peer to a
	// server. The map must not be manipulated after adding the peer, but network
	// paths may be added and removed from a table at any time.
	//
	// Tables may be safely shared across multiple peers or by import and export
	// use cases.
	Import map[RouteFamily]*Table

	// Export stores the network reachability information to be announced to the
	// peer. See the documentation on Import for usage details.
	Export map[RouteFamily]*Table

	// ImportFilters run for each path received from a peer before it is inserted
	// into the import table.
	ImportFilters []Filter

	// ExportFilters run for each path to be announced to a peer.
	ExportFilters []Filter

	// Timers holds optional parameters to control the hold time and keepalive of
	// the BGP session.
	Timers *Timers

	// DialerControl is called after creating the network connection but before
	// actually dialing. See https://pkg.go.dev/net#Dialer.Control for details.
	DialerControl func(network, address string, c syscall.RawConn) error

	fsm     *fsm
	dynamic bool
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
	if p.Addr.Is6() {
		return "[" + p.Addr.String() + "]:" + strconv.Itoa(port)
	}
	return p.Addr.String() + ":" + strconv.Itoa(port)
}

func (p *Peer) transportAFI() uint16 {
	for _, a := range []netip.Addr{p.LocalAddr, p.Addr} {
		switch {
		case a.Is4():
			return bgp.AFI_IP
		case a.Is6():
			return bgp.AFI_IP6
		}
	}
	return 0
}

func (p *Peer) supportsRouteFamily(rf RouteFamily) bool {
	return p.Import[rf] != nil || p.Export[rf] != nil
}

func (p *Peer) start(s *Server) {
	if p.fsm != nil {
		p.fsm.server.fatalf("tried to start the same peer twice")
	}
	p.fsm = &fsm{
		server:        s,
		peer:          p,
		timers:        newTimers(p.Timers),
		exportFilters: p.ExportFilters,
		acceptC:       make(chan net.Conn, 1),
		stopC:         make(chan struct{}),
		doneC:         make(chan struct{}),
	}
	go p.fsm.run(p)
}

func (p *Peer) stop() {
	p.fsm.stop()
}
