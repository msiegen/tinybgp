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
	"slices"
	"strconv"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

var (
	noExportCommunity = NewCommunity(uint32(bgp.COMMUNITY_NO_EXPORT))
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

	// ImportFilter decides whether to import a path into the import table and
	// optionally modifies it. If not provided, the DefaultImportFilter method
	// is used.
	ImportFilter Filter

	// ExportFilter decides whether to export a path to the peer and optionally
	// modifies it. If not provided, the DefaultExportFilter method is used.
	ExportFilter Filter

	// Timers holds optional parameters to control the hold time and keepalive of
	// the BGP session.
	Timers *Timers

	// DialerControl is called after creating the network connection but
	// before actually dialing. See https://pkg.go.dev/net#Dialer.Control
	// for background. To configure TCP MD5 authentication, set it to
	// tcpmd5.DialerControl("password").
	DialerControl func(network, address string, c syscall.RawConn) error

	// ConfigureListener is called for each of the server's listeners upon
	// adding the peer. To configure TCP MD5 authentication, set it to
	// tcpmd5.ConfigureListener("2001:db8::1234", "password"), making
	// sure that the IP address matches the one in Addr.
	ConfigureListener func(l net.Listener) error

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

func (p *Peer) start(s *Server) error {
	if p.fsm != nil {
		return errors.New("tried to start the same peer twice")
	}
	p.fsm = &fsm{
		server:       s,
		peer:         p,
		timers:       newTimers(p.Timers),
		exportFilter: p.exportFilter,
		acceptC:      make(chan net.Conn, 1),
		stopC:        make(chan struct{}),
		doneC:        make(chan struct{}),
	}
	go p.fsm.run(p)
	return nil
}

func (p *Peer) stop() {
	p.fsm.stop()
}

// DefaultImportFilter is the default filter when no ImportFilter is provided.
// It discards routes that contain the local ASN in their AS path.
func (p *Peer) DefaultImportFilter(prefix netip.Prefix, path *Path) error {
	if slices.Contains(path.ASPath, p.fsm.server.ASN) {
		return ErrDiscard
	}
	return nil
}

func (p *Peer) importFilter(prefix netip.Prefix, path *Path) error {
	if p.ImportFilter != nil {
		return p.ImportFilter(prefix, path)
	}
	return p.DefaultImportFilter(prefix, path)
}

// DefaultExportFilter is the default filter when no ExportFilter is provided.
// It prepends the local ASN to the AS path, changes the nexthop to the local
// IP of the peering session, and discards routes bearing the "no export" well
// known community.
func (p *Peer) DefaultExportFilter(prefix netip.Prefix, path *Path) error {
	if slices.Contains(path.Communities, noExportCommunity) {
		return ErrDiscard
	}
	path.ASPath = append([]uint32{p.fsm.server.ASN}, path.ASPath...)
	path.Nexthop = p.fsm.session.LocalIP
	return nil
}

func (p *Peer) exportFilter(prefix netip.Prefix, path *Path) error {
	if p.ExportFilter != nil {
		return p.ExportFilter(prefix, path)
	}
	return p.DefaultExportFilter(prefix, path)
}
