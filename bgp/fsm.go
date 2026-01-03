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

// This file implements the progression of states in:
// https://www.ciscopress.com/articles/article.asp?p=2756480&seqNum=4
// https://networklessons.com/bgp/bgp-neighbor-adjacency-states

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/jpillora/backoff"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	// state_BGP_FSM_ERROR is an additional state in the FSM that is used to
	// handle errors.
	state_BGP_FSM_ERROR = bgp.FSMState(98)
	// state_BGP_FSM_TERMINATE is an additional state in the FSM that is used as a
	// signal to terminate the run loop.
	state_BGP_FSM_TERMINATE = bgp.FSMState(99)
	// LevelUpdates is a log level between INFO and DEBUG, used for high volume
	// events associated with BGP UPDATE messages (announcements and withdrawals).
	LevelUpdates slog.Level = -2
)

// formatState prints the name of a state for use in log messages. The strings
// here are a bit more concise than the ones in GoBGP.
func formatState(s bgp.FSMState) string {
	switch s {
	case bgp.BGP_FSM_IDLE:
		return "IDLE"
	case bgp.BGP_FSM_CONNECT:
		return "CONNECT"
	case bgp.BGP_FSM_ACTIVE:
		return "ACTIVE"
	case bgp.BGP_FSM_OPENSENT:
		return "OPENSENT"
	case bgp.BGP_FSM_OPENCONFIRM:
		return "OPENCONFIRM"
	case bgp.BGP_FSM_ESTABLISHED:
		return "ESTABLISHED"
	case state_BGP_FSM_ERROR:
		return "ERROR"
	case state_BGP_FSM_TERMINATE:
		return "TERMINATE"
	default:
		return "UNKNOWN"
	}
}

// session holds data with a lifetime matching a BGP session TCP connection.
type session struct {
	// Families is the intersection of AFI/SAFI tuples that are supported by
	// both the local server and the peer.
	Families map[Family]bool
	// PeerASN is the peer's AS number.
	PeerASN uint32
	// LocalIP holds a copy of the local IP address, used to populate the
	// nexthop field in UPDATE messages.
	LocalIP netip.Addr
	// Tracked holds the routes considered for export to this peer. It includes
	// the routes that were announced to the peer as well as the ones suppressed
	// by an export filter.
	Tracked map[Family]map[netip.Prefix]attrHandle
	// Suppressed holds the routes that were rejected by an export filter.
	Suppressed map[Family]map[netip.Prefix]struct{}
	// Version is the version of the routing table last sent to the peer.
	Version int64
	// RecvDone is initialized when the receive loop starts and closed when the
	// receive loop terminates. It provides a synchronization signal for session
	// teardown to ensure that cleanup doesn't run while the receive loop might
	// still be inserting routes into the table.
	RecvDone <-chan struct{}
	// Cleared is true after any received routes have been cleared out of the
	// local table.
	Cleared bool
	// Logger is a structured logger. Must not be nil.
	Logger *slog.Logger
}

// newSession creates a new session with a non-nil logger.
func newSession(logger *slog.Logger, peerAddr netip.Addr) session {
	if logger == nil {
		logger = discardLogger
	} else {
		logger = logger.With("peer", peerAddr)
	}
	return session{
		Logger: logger,
	}
}

// setPeerHostDomain updates the session's logger to attach the peer's host and
// domain name. It should be called once upon receiving that information from
// the peer's OPEN message.
func (s *session) setPeerHostDomain(host, domain string) {
	if s.Logger == discardLogger {
		return
	}
	switch {
	case host != "" && domain != "":
		s.Logger = s.Logger.With("peer_host", host, "peer_domain", domain)
	case host != "":
		s.Logger = s.Logger.With("peer_host", host)
	case domain != "":
		s.Logger = s.Logger.With("peer_domain", domain)
	}
}

// initCache initializes the cache of which paths have been sent to the peer.
// It must be called upon connection establishment.
func (s *session) initCache() {
	s.Tracked = map[Family]map[netip.Prefix]attrHandle{}
	s.Suppressed = map[Family]map[netip.Prefix]struct{}{}
	for rf := range s.Families {
		s.Tracked[rf] = map[netip.Prefix]attrHandle{}
		s.Suppressed[rf] = map[netip.Prefix]struct{}{}
	}
}

// setLocalIP initializes the LocalIP field. It must be called once upon
// connection establishment.
func (s *session) setLocalIP(c net.Conn) {
	s.LocalIP, _ = netip.AddrFromSlice(c.LocalAddr().(*net.TCPAddr).IP)
}

type fsm struct {
	server       *Server
	peer         *Peer
	timers       *Timers
	exportFilter Filter
	// acceptC is used to pass incomming connections from the Server.acceptLoop
	// to fsm.run.
	acceptC chan net.Conn
	//mu sync.Mutex
	state   bgp.FSMState
	session session
	// stopC will be closed to signal the run loop to terminate.
	stopC chan struct{}
	// doneC will be closed when the run loop has terminated.
	doneC chan struct{}
}

func (f *fsm) getState() bgp.FSMState {
	return f.state
}

func (f *fsm) setStateWithoutLog(s bgp.FSMState) {
	f.state = s
}

func (f *fsm) setState(ctx context.Context, s bgp.FSMState) {
	if l := f.session.Logger; l.Enabled(ctx, slog.LevelInfo) {
		l.Info("session changed state", "state", formatState(s), "prev_state", formatState(f.state))
	}
	f.setStateWithoutLog(s)
}

func (f *fsm) setStateError(ctx context.Context, peer *Peer, e error) {
	nextState := state_BGP_FSM_ERROR
	if l := f.session.Logger; l.Enabled(ctx, slog.LevelError) {
		// TODO: If the error is due to the receipt of a NOTIFICATION, extract
		// the code, subcode, and data and log them as attributes.
		l.Error("session changed state", "state", formatState(nextState), "prev_state", formatState(f.state), "details", e)
	}
	f.setStateWithoutLog(nextState)
}

// fsmDialPeer attempts to connect to the peer in the background, and returns
// the opened connection or error on a channel. If the caller does not read from
// the channel within a short time of the connection being established, the
// connection will automatically be closed. It is safe for callers to abandon a
// a dial attempt and never read from either channel.
func fsmDialPeer(d *net.Dialer, addr string) (<-chan net.Conn, <-chan error) {
	// connC has no buffer because we want to detect when the channel is read.
	connC := make(chan net.Conn)
	// errC has a buffer to avoid a resource leak if the caller abandons the dial.
	errC := make(chan error, 1)
	go func(connC chan<- net.Conn, errC chan<- error) {
		c, err := d.Dial("tcp", addr)
		if err != nil {
			errC <- err
			return
		}
		select {
		case connC <- c:
		case <-time.After(3 * time.Second):
			// We've lost the race against an incomming connection. Close ours.
			c.Close()
		}
	}(connC, errC)
	return connC, errC
}

// fsmSendMessage sends a BGP message to the peer.
func fsmSendMessage(c net.Conn, m *bgp.BGPMessage, timeout time.Duration) error {
	b, err := m.Serialize()
	if err != nil {
		return err
	}
	if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

func isValidMarker(marker []byte) bool {
	if len(marker) != 16 {
		return false
	}
	for _, b := range marker {
		if b != 0xff {
			return false
		}
	}
	return true
}

// fsmRecvMessage reads a single BGP message from the peer. It requires a buffer
// of length bgp.BGP_MAX_MESSAGE_LENGTH. The buffer escapes to the heap due to
// limitations in Go escape analysis, so the caller should allocate a reusable
// one to minimize garbage.
func fsmRecvMessage(c net.Conn, buf []byte, deadline time.Time) (*bgp.BGPMessage, error) {
	if err := c.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(c, buf[:bgp.BGP_HEADER_LENGTH]); err != nil {
		return nil, err
	}
	// DecodeFromBytes neither validates the marker nor populates the Marker field
	// in bgp.BGPHeader, so we'll validate it in the original buffer directly.
	if !isValidMarker(buf[:16]) {
		return nil, bgp.NewMessageError(bgp.BGP_ERROR_MESSAGE_HEADER_ERROR, bgp.BGP_ERROR_SUB_CONNECTION_NOT_SYNCHRONIZED, nil, "connection not synchronized")
	}
	var h bgp.BGPHeader
	if err := h.DecodeFromBytes(buf[:bgp.BGP_HEADER_LENGTH]); err != nil {
		return nil, err
	}
	if h.Len > bgp.BGP_MAX_MESSAGE_LENGTH {
		return nil, bgp.NewMessageError(bgp.BGP_ERROR_MESSAGE_HEADER_ERROR, bgp.BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "received message is too long")
	}
	if _, err := io.ReadFull(c, buf[bgp.BGP_HEADER_LENGTH:h.Len]); err != nil {
		return nil, err
	}
	// If we want to optimize this in the future, the parse function could be
	// reimplemented with one that populates a provided bgp.BGPUpdate struct and
	// avoids creating garbage for the common case of an UPDATE message. To get
	// the maximum benefit it may be necessary to also reimplement bgp.BGPUpdate
	// to not contain any pointers.
	return bgp.ParseBGPBody(&h, buf[bgp.BGP_HEADER_LENGTH:h.Len])
}

// twoByteASN validates an ASN and returns a 2-byte ASN for use in the OPEN
// message. This is either 23456 (for 4-byte ASNs) or the original ASN (if it
// fits in 2-bytes).
func twoByteASN(asn uint32) (uint16, error) {
	switch asn {
	case 0, 23456, 65535, 4294967295:
		return 0, fmt.Errorf("invalid asn: %v", asn)
	default:
		if asn < 65535 {
			return uint16(asn), nil
		}
		return bgp.AS_TRANS, nil
	}
}

// sendOpen sends an OPEN.
func (f *fsm) sendOpen(c net.Conn, transportAFI uint16) error {
	// TODO: Implement support and add bgp.NewCapRouteRefresh() ?
	caps := make([]bgp.ParameterCapabilityInterface, 0, 6)
	if f.server.Hostname != "" {
		caps = append(caps, bgp.NewCapFQDN(f.server.Hostname, f.server.Domainname))
	}
	caps = append(caps, bgp.NewCapFourOctetASNumber(f.server.ASN))
	supportsIPv4 := f.peer.supportsFamily(IPv4Unicast)
	if supportsIPv4 {
		caps = append(caps, bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC))
	}
	supportsIPv6 := f.peer.supportsFamily(IPv6Unicast)
	if supportsIPv6 {
		caps = append(caps, bgp.NewCapMultiProtocol(bgp.RF_IPv6_UC))
	}
	if !supportsIPv4 && !supportsIPv6 {
		return errors.New("local RIB must support at least one of IPv4 or IPv6")
	}
	switch transportAFI {
	case bgp.AFI_IP:
		if supportsIPv6 {
			caps = append(caps, bgp.NewCapExtendedNexthop([]*bgp.CapExtendedNexthopTuple{
				bgp.NewCapExtendedNexthopTuple(bgp.RF_IPv6_UC, bgp.AFI_IP),
			}))
		}
	case bgp.AFI_IP6:
		if supportsIPv4 {
			caps = append(caps, bgp.NewCapExtendedNexthop([]*bgp.CapExtendedNexthopTuple{
				bgp.NewCapExtendedNexthopTuple(bgp.RF_IPv4_UC, bgp.AFI_IP6),
			}))
		}
	case 0:
		return errors.New("unable to determine transport AFI")
	}
	as, err := twoByteASN(f.server.ASN)
	if err != nil {
		return err
	}
	holdTime := uint16(f.timers.HoldTime / time.Second)
	m := bgp.NewBGPOpenMessage(as, holdTime, f.server.RouterID, []bgp.OptionParameterInterface{
		bgp.NewOptionParameterCapability(caps),
	})
	return fsmSendMessage(c, m, defaultOpenTimeout)
}

func openCapabilities(o *bgp.BGPOpen) ([]bgp.ParameterCapabilityInterface, error) {
	var caps []bgp.ParameterCapabilityInterface
	for _, p := range o.OptParams {
		if c, ok := p.(*bgp.OptionParameterCapability); ok {
			caps = append(caps, c.Capability...)
		}
	}
	if len(caps) == 0 {
		return nil, errors.New("missing capabilities")
	}
	return caps, nil
}

// validateOpen checks the OPEN message received from the peer. It returns an
// error subcode that may be combined with code bgp.BGP_ERROR_OPEN_MESSAGE_ERROR
// into a NOTIFICATION message back to the peer.
func validateOpen(o *bgp.BGPOpen, transportAFI uint16, peer *Peer, serverLogger *slog.Logger) (session, uint8, error) {
	// We only support BGP-4, https://datatracker.ietf.org/doc/html/rfc4271.
	if o.Version != 4 {
		return session{}, bgp.BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER, fmt.Errorf("unsupported BGP version: %v", o.Version)
	}
	// Parse the capabilities advertised by the peer.
	caps, err := openCapabilities(o)
	if err != nil {
		return session{}, bgp.BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER, err
	}
	var fourByteAS uint32
	sess := newSession(serverLogger, peer.Addr) // create new session
	sess.Families = map[Family]bool{}
	extendedNexthops := map[bgp.CapExtendedNexthopTuple]bool{}
	for _, cc := range caps {
		switch c := cc.(type) {
		case *bgp.CapFourOctetASNumber:
			fourByteAS = c.CapValue
		case *bgp.CapMultiProtocol:
			switch {
			case c.CapValue == bgp.RF_IPv4_UC && peer.supportsFamily(IPv4Unicast):
				sess.Families[IPv4Unicast] = true
			case c.CapValue == bgp.RF_IPv6_UC && peer.supportsFamily(IPv6Unicast):
				sess.Families[IPv6Unicast] = true
			}
		case *bgp.CapExtendedNexthop:
			for _, t := range c.Tuples {
				extendedNexthops[*t] = true
			}
		case *bgp.CapFQDN:
			// Augment the session's logger with the host and domain name.
			if c.DomainNameLen == 0 {
				c.DomainName = "" // workaround GoBGP bug
			}
			sess.setPeerHostDomain(c.HostName, c.DomainName)
		}
	}
	// Abort if the peer doesn't support 4-byte AS numbers. That should be rare,
	// and establishing an invariant here simplifies the logic in sendUpdate.
	if fourByteAS == 0 {
		return session{}, bgp.BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, errors.New("missing support for 4-byte AS numbers")
	}
	sess.PeerASN = fourByteAS
	// Ensure that the local address of an IPv4 BGP session can be used as a
	// nexthop for IPv6 routes announced via the session, and vice versa. If the
	// peer doesn't support this, limit the session to only announce routes of the
	// same family as the session transport.
	switch transportAFI {
	case bgp.AFI_IP:
		if !extendedNexthops[bgp.CapExtendedNexthopTuple{bgp.AFI_IP6, bgp.SAFI_UNICAST, bgp.AFI_IP}] {
			delete(sess.Families, IPv6Unicast)
		}
	case bgp.AFI_IP6:
		if !extendedNexthops[bgp.CapExtendedNexthopTuple{bgp.AFI_IP, bgp.SAFI_UNICAST, bgp.AFI_IP6}] {
			delete(sess.Families, IPv4Unicast)
		}
	default:
		return session{}, 0, errors.New("unable to determine transport AFI")
	}
	// At least one of IPv4 or IPv6 unicast must be supported.
	if !sess.Families[IPv4Unicast] && !sess.Families[IPv6Unicast] {
		return session{}, bgp.BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, errors.New("must support at least one of ipv4 or ipv6")
	}
	// Validate the peer AS number, if we know what it should be.
	if peer.ASN != 0 {
		if peer.ASN < 0xffff {
			if o.MyAS != uint16(peer.ASN) {
				return session{}, bgp.BGP_ERROR_SUB_BAD_PEER_AS, fmt.Errorf("wrong peer AS: got %v, want %v", o.MyAS, peer.ASN)
			}
		} else {
			if o.MyAS != bgp.AS_TRANS {
				return session{}, bgp.BGP_ERROR_SUB_BAD_PEER_AS, fmt.Errorf("wrong peer AS: got %v, want transition %v", o.MyAS, bgp.AS_TRANS)
			}
		}
		if fourByteAS != peer.ASN {
			return session{}, bgp.BGP_ERROR_SUB_BAD_PEER_AS, fmt.Errorf("wrong peer AS in 4-byte capability: got %v, want %v", fourByteAS, peer.ASN)
		}
	}
	// Ensure the hold time is not too short or too long.
	if o.HoldTime < 3 {
		return session{}, bgp.BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME, fmt.Errorf("hold time is too short: %v", o.HoldTime)
	}
	if o.HoldTime > 600 {
		return session{}, bgp.BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME, fmt.Errorf("hold time is too long: %v", o.HoldTime)
	}
	// Success!
	return sess, 0, nil
}

// fsmSendKeepAlive sends a KEEPALIVE.
func fsmSendKeepAlive(c net.Conn, timeout time.Duration) error {
	m := bgp.NewBGPKeepAliveMessage()
	return fsmSendMessage(c, m, timeout)
}

// newIPAddrPrefix returns an IPv4 or IPv6 address prefix.
func newIPAddrPrefix(n netip.Prefix) (bgp.AddrPrefixInterface, error) {
	a := n.Addr()
	switch {
	case !n.IsValid():
		return nil, errors.New("invalid prefix")
	case a.Is4():
		return bgp.NewIPAddrPrefix(uint8(n.Bits()), a.String()), nil
	case a.Is6():
		return bgp.NewIPv6AddrPrefix(uint8(n.Bits()), a.String()), nil
	}
	return nil, errors.New("prefix is neither ipv4 nor ipv6")
}

// sendUpdate sends an UPDATE announcing a new or changed path.
func (f *fsm) sendUpdate(c net.Conn, network netip.Prefix, attrs Attributes) error {
	// We can safely send 4-byte AS numbers here because validateOpen enforced
	// that the remote end supports it.
	asp := bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, attrs.Path())
	ap, err := newIPAddrPrefix(network)
	if err != nil {
		return err
	}
	nexthop := attrs.Nexthop()
	if !nexthop.IsValid() {
		return fmt.Errorf("invalid nexthop for prefix %v", network)
	}
	a := make([]bgp.PathAttributeInterface, 0, 4)
	var nlri []*bgp.IPAddrPrefix
	if network.Addr().Is4() && nexthop.Is4() {
		// For IPv4 routed via an IPv4 nexthop, use the the NLRI field in the UPDATE
		// message and populate the mandatory NEXT_HOP attribute as required by
		// https://datatracker.ietf.org/doc/html/rfc4271.
		a = append(a, bgp.NewPathAttributeNextHop(nexthop.String()))
		nlri = []*bgp.IPAddrPrefix{
			bgp.NewIPAddrPrefix(uint8(network.Bits()), network.Addr().String()),
		}
	} else {
		// For IPv6 or IPv4 routed via an IPv6 nexthop, use the MP_REACH_NLRI
		// attribute as required by https://datatracker.ietf.org/doc/html/rfc4760.
		// According to https://datatracker.ietf.org/doc/html/rfc7606#section-5.1
		// this should be the first attribute.
		a = append(a, bgp.NewPathAttributeMpReachNLRI(nexthop.String(), []bgp.AddrPrefixInterface{ap}))
	}
	a = append(a,
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_INCOMPLETE),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{asp}),
	)
	if med, ok := attrs.MED(); ok {
		a = append(a, bgp.NewPathAttributeMultiExitDisc(med))
	}
	cm := attrs.Communities()
	if len(cm) != 0 {
		cs := make([]uint32, 0, len(cm))
		for c := range cm {
			cs = append(cs, c.Uint32())
		}
		a = append(a, bgp.NewPathAttributeCommunities(cs))
	}
	lcm := attrs.LargeCommunities()
	if len(lcm) != 0 {
		cs := make([]*bgp.LargeCommunity, 0, len(lcm))
		for c := range lcm {
			cs = append(cs, &bgp.LargeCommunity{c.ASN, c.Data1, c.Data2})
		}
		a = append(a, bgp.NewPathAttributeLargeCommunities(cs))
	}
	m := bgp.NewBGPUpdateMessage(nil, a, nlri)
	return fsmSendMessage(c, m, defaultMessageTimeout)
}

// sendWithdraw sends an UPDATE withdrawing a path.
func (f *fsm) sendWithdraw(c net.Conn, network netip.Prefix) error {
	ap, err := newIPAddrPrefix(network)
	if err != nil {
		return err
	}
	var m *bgp.BGPMessage
	if network.Addr().Is4() {
		m = bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{
			bgp.NewIPAddrPrefix(uint8(network.Bits()), network.Addr().String()),
		}, nil, nil)
	} else {
		m = bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeMpUnreachNLRI([]bgp.AddrPrefixInterface{ap}),
		}, nil)
	}
	return fsmSendMessage(c, m, defaultMessageTimeout)
}

// sendUpdates informs the peer of any paths that have changed since the last
// call to sendUpdates.
func (f *fsm) sendUpdates(ctx context.Context, c net.Conn, reevaluate bool) (bool, error) {
	var alive bool
	for rf, table := range f.peer.Export {
		if !f.session.Families[rf] {
			// Skip route families not supported by the peer.
			continue
		}
		tracked := f.session.Tracked[rf]
		suppressed := f.session.Suppressed[rf]
		for nlri, attrs := range table.updatedRoutes(f.exportFilter, tracked, suppressed, &f.session.Version, reevaluate) {
			if attrs.Nexthop().IsValid() {
				f.session.Logger.Log(ctx, LevelUpdates, "announcing", "nlri", nlri)
				if err := f.sendUpdate(c, nlri, attrs); err != nil {
					return false, err
				}
			} else {
				f.session.Logger.Log(ctx, LevelUpdates, "withdrawing", "nlri", nlri)
				if err := f.sendWithdraw(c, nlri); err != nil {
					return false, err
				}
			}
			alive = true
		}
	}
	return alive, nil
}

// notification is a NOTIFICATION message.
type notification struct {
	ErrorCode, ErrorSubcode uint8
}

// fsmSendNotification sends a NOTIFICATION to inform the peer of an error.
func fsmSendNotification(c net.Conn, errcode, errsubcode uint8, data []byte) error {
	m := bgp.NewBGPNotificationMessage(errcode, errsubcode, data)
	return fsmSendMessage(c, m, defaultNotificationTimeout)
}

// maybeSendNotification sends a NOTIFICATION if the passed error contains a
// bgp.MessageError and does nothing otherwise.
func maybeSendNotification(c net.Conn, e error) error {
	var me *bgp.MessageError
	if errors.As(e, &me) {
		return fsmSendNotification(c, me.TypeCode, me.SubTypeCode, me.Data)
	}
	return nil
}

// sendLoop launches a background goroutine to handle outgoing messages.
func (f *fsm) sendLoop(ctx context.Context, c net.Conn) (chan<- notification, <-chan error) {
	// notifyC needs a buffer of 2 because either the run or recvLoop function may
	// wish to transmit a NOTIFICATION.
	notifyC := make(chan notification, 2)
	errC := make(chan error, 1)
	go func(notifyC <-chan notification, errC chan<- error) {
		version := f.peer.exportFilterVersion.Load()
		var delay time.Duration
		nextKeepAlive := time.Now().Add(f.timers.NextKeepAlive())
		for {
			select {
			case <-time.After(delay):
				delay = 1 * time.Second
				newVersion := f.peer.exportFilterVersion.Load()
				reevaluate := newVersion != version
				ok, err := f.sendUpdates(ctx, c, reevaluate)
				if err != nil {
					errC <- err
					return
				}
				version = newVersion
				if ok {
					// We sent at least one update, so can reset the keepalive timer.
					nextKeepAlive = time.Now().Add(f.timers.NextKeepAlive())
					continue
				}
				if time.Now().Before(nextKeepAlive) {
					// We don't need to send another KEEPALIVE yet.
					continue
				}
				// Send a KEEPALIVE to hold the session open.
				if err := fsmSendKeepAlive(c, f.timers.HoldTime); err != nil {
					errC <- err
					return
				}
				nextKeepAlive = time.Now().Add(f.timers.NextKeepAlive())
			case n := <-notifyC:
				if n.ErrorCode == 0 && n.ErrorSubcode == 0 {
					// We've been asked to terminate without sending a NOTIFICATION.
					errC <- nil
				} else {
					errC <- fsmSendNotification(c, n.ErrorCode, n.ErrorSubcode, nil)
				}
				return
			}
		}
	}(notifyC, errC)
	return notifyC, errC
}

func (f *fsm) processUpdate(ctx context.Context, peerAddr netip.Addr, importFilter Filter, m *bgp.BGPUpdate) {
	var (
		afi       uint16
		safi      uint8
		nexthop   netip.Addr
		med       uint32
		hasMED    bool
		updated   []netip.Prefix
		withdrawn []netip.Prefix
		asPath    []uint32
	)
	communities := map[Community]bool{}
	extendedCommunities := map[ExtendedCommunity]bool{}
	largeCommunities := map[LargeCommunity]bool{}
	for _, nlri := range m.NLRI {
		// Announcement for IPv4 via an IPv4 nexthop
		addr, _ := netip.AddrFromSlice(nlri.Prefix)
		if p := netip.PrefixFrom(addr, int(nlri.Length)); p.IsValid() {
			updated = append(updated, p)
		}
		afi = bgp.AFI_IP
		safi = bgp.SAFI_UNICAST
	}
	for _, nlri := range m.WithdrawnRoutes {
		// Withdrawal for IPv4 via an IPv4 nexthop
		addr, _ := netip.AddrFromSlice(nlri.Prefix)
		if p := netip.PrefixFrom(addr, int(nlri.Length)); p.IsValid() {
			withdrawn = append(withdrawn, p)
		}
		afi = bgp.AFI_IP
		safi = bgp.SAFI_UNICAST
	}
	for _, pa := range m.PathAttributes {
		switch a := pa.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			// Announcement for IPv6 or IPv4 via an IPv6 nexthop
			afi = a.AFI
			safi = a.SAFI
			nexthop, _ = netip.AddrFromSlice(a.Nexthop)
			for _, addr := range a.Value {
				if nlri, err := netip.ParsePrefix(addr.String()); err == nil {
					updated = append(updated, nlri)
				}
			}
		case *bgp.PathAttributeMpUnreachNLRI:
			// Withdrawal for IPv6 or IPv4 via an IPv6 nexthop
			afi = a.AFI
			safi = a.SAFI
			for _, addr := range a.Value {
				if nlri, err := netip.ParsePrefix(addr.String()); err == nil {
					withdrawn = append(withdrawn, nlri)
				}
			}
		case *bgp.PathAttributeNextHop:
			nexthop, _ = netip.AddrFromSlice(a.Value)
		case *bgp.PathAttributeAsPath:
			for _, ases := range a.Value {
				asPath = append(asPath, ases.GetAS()...)
			}
		case *bgp.PathAttributeMultiExitDisc:
			med = a.Value
			hasMED = true
		case *bgp.PathAttributeCommunities:
			for _, v := range a.Value {
				communities[NewCommunity(v)] = true
			}
		case *bgp.PathAttributeExtendedCommunities:
			for _, v := range a.Value {
				if b, err := v.Serialize(); err == nil { // if no error
					if c, err := newExtendedCommunity(b); err == nil { // if no error
						extendedCommunities[c] = true
					}
				}
			}
		case *bgp.PathAttributeLargeCommunities:
			for _, v := range a.Values {
				largeCommunities[LargeCommunity{v.ASN, v.LocalData1, v.LocalData2}] = true
			}
		}
	}
	rf := NewFamily(afi, safi)
	if !f.session.Families[rf] {
		// Ignore route families not previously negotiated with the peer. A well
		// behaved peer should not send them.
		return
	}
	table := f.peer.Import[rf]
	if table == nil {
		// Ignore route families that don't exist in our import table. This can
		// happen if our import and export tables are configured differently.
		return
	}
	for _, nlri := range withdrawn {
		if table.hasNetwork(nlri) {
			table.RemovePath(nlri, peerAddr)
		}
	}
	if nexthop.IsLinkLocalUnicast() {
		nexthop = nexthop.WithZone(peerAddr.Zone())
	}
	for _, nlri := range updated {
		var attrs Attributes
		attrs.SetPeer(peerAddr)
		attrs.SetNexthop(nexthop)
		if hasMED {
			attrs.SetMED(med)
		}
		attrs.SetPath(asPath)
		attrs.SetCommunities(communities)
		attrs.SetExtendedCommunities(extendedCommunities)
		attrs.SetLargeCommunities(largeCommunities)
		attrs, err := importFilter(nlri, attrs)
		if err != nil {
			if errors.Is(err, ErrDiscard) {
				f.session.Logger.Log(ctx, LevelUpdates, "import filter discarded", "nlri", nlri)
			} else {
				f.session.Logger.Error("import filter failed", "nlri", nlri, "details", err)
			}
			// If an NLRI was previously accepted but should now be filtered,
			// remove it from the table.
			if table.hasNetwork(nlri) {
				table.RemovePath(nlri, peerAddr)
			}
			continue
		}
		f.session.Logger.Log(ctx, LevelUpdates, "importing", "nlri", nlri)
		table.AddPath(nlri, attrs)
	}
}

// isFramingError returns true if the connecton is unsynchronized or a message
// header has a bad length. These cases are unrecoverable and require the
// session to be torn down.
func isFramingError(e *bgp.MessageError) bool {
	return e.TypeCode == bgp.BGP_ERROR_MESSAGE_HEADER_ERROR && e.SubTypeCode != bgp.BGP_ERROR_SUB_BAD_MESSAGE_TYPE
}

// recvLoop launches a background goroutine to handle incomming messages.
func (f *fsm) recvLoop(ctx context.Context, c net.Conn, peerAddr netip.Addr, importFilter Filter, holdTime time.Duration, notifyC chan<- notification) (<-chan error, <-chan struct{}) {
	errC := make(chan error, 1)
	doneC := make(chan struct{})
	go func(errC chan<- error, doneC chan<- struct{}) {
		defer close(doneC)
		deadline := time.Now().Add(holdTime)
		var buf [bgp.BGP_MAX_MESSAGE_LENGTH]byte
		for {
			msg, err := fsmRecvMessage(c, buf[:], deadline)
			if err != nil {
				var me *bgp.MessageError
				if errors.As(err, &me) && !isFramingError(me) {
					// Ignore the bad message. We don't want to tear down the session just
					// because an UPDATE, possibly from far away on the internet, contains
					// data that GoBGP doesn't understand.
					f.session.Logger.Warn("ignoring bad message", "code", me.TypeCode, "subcode", me.SubTypeCode, "details", err)
					continue
				}
				errC <- err // Unblock recvErrC in func run before sendErrC.
				switch {
				case time.Now().After(deadline):
					notifyC <- notification{bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, bgp.BGP_ERROR_SUB_HOLD_TIMER_EXPIRED}
				default:
					notifyC <- notification{}
				}
				return
			}
			switch m := msg.Body.(type) {
			case *bgp.BGPUpdate:
				deadline = time.Now().Add(holdTime)
				f.processUpdate(ctx, peerAddr, importFilter, m)
			case *bgp.BGPKeepAlive:
				deadline = time.Now().Add(holdTime)
			case *bgp.BGPNotification:
				errC <- fmt.Errorf("notification: code=%v subcode=%v data=%q", m.ErrorCode, m.ErrorSubcode, string(m.Data))
				notifyC <- notification{}
				return
			default:
				errC <- fmt.Errorf("received unexpected message type %v", msg.Header.Type)
				notifyC <- notification{bgp.BGP_ERROR_FSM_ERROR, bgp.BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE}
				return
			}
		}
	}(errC, doneC)
	return errC, doneC
}

// removePaths removes all paths from the specified peer.
func (f *fsm) removePaths(peerAddr netip.Addr) {
	for rf, table := range f.peer.Import {
		if !f.session.Families[rf] {
			// Skip route families not previously negotiated with the peer.
			continue
		}
		table.removePathsFrom(peerAddr)
	}
}

// run executes the BGP state machine.
func (f *fsm) run(ctx context.Context, peer *Peer) {
	dialer := &net.Dialer{
		Timeout:   defaultOpenTimeout,
		LocalAddr: peer.localAddr(),
		KeepAlive: -1,
		Control:   peer.DialerControl,
	}
	transportAFI := peer.transportAFI()
	peerAddr := peer.addr()
	connectBackoff := backoff.Backoff{
		Factor: 1.5,
		Jitter: true,
		Min:    1 * time.Second,
		Max:    90 * time.Second,
	}
	var connecting bool
	var collisionDetector *collisionDetector
	var bgpConn net.Conn
	var holdTime time.Duration
	var buf [bgp.BGP_MAX_MESSAGE_LENGTH]byte
	for {
		switch f.getState() {
		case bgp.BGP_FSM_IDLE:
			// Create a new session to clear out any leftover state from previous
			// trips through the state machine, and to give ourselves a logger for use
			// while attempting to connect. This session will be replaced with a more
			// fully populated one upon receiving a valid OPEN message from the peer.
			f.session = newSession(f.server.logger(), peer.Addr)
			var readyToConnect <-chan time.Time
			if !peer.Passive {
				readyToConnect = time.After(connectBackoff.Duration())
			}
			connecting = false
			select {
			case c := <-collisionDetector.Chan():
				// We have an incomming connection that collided with an earlier
				// outgoing dial and was selected as preferred. Grab it and jump
				// straight to state ESTABLISHED.
				bgpConn = c
				// Replace the initial session with the one created by validateOpen.
				f.session = collisionDetector.session
				f.setState(ctx, bgp.BGP_FSM_ESTABLISHED)
			case c := <-f.acceptC:
				// We have a new connection.
				bgpConn = c
				f.setState(ctx, bgp.BGP_FSM_ACTIVE)
				// TODO: In all later states, also watch f.acceptC and close any
				// connections that happen to be received.
			case <-readyToConnect:
				f.setState(ctx, bgp.BGP_FSM_CONNECT)
				connecting = true
			case <-f.stopC:
				f.setState(ctx, state_BGP_FSM_TERMINATE)
			}
			collisionDetector.Stop()
			collisionDetector = nil

		case bgp.BGP_FSM_CONNECT:
			// Make an outgoing connection in the background.
			connC, errC := fsmDialPeer(dialer, peerAddr)
			// Wait for a connection to be established.
			select {
			case c := <-connC:
				bgpConn = c
				f.setState(ctx, bgp.BGP_FSM_ACTIVE)
			case err := <-errC:
				f.setStateError(ctx, peer, err)
			case <-f.stopC:
				f.setState(ctx, state_BGP_FSM_TERMINATE)
			}
			// TODO: If we get an incomming connection, accept it and jump to state
			// ACTIVE. Maybe this can be done by starting the colision handler earlier
			// and indirecting back through the IDLE state?

		case bgp.BGP_FSM_ACTIVE:
			if err := f.sendOpen(bgpConn, transportAFI); err != nil {
				bgpConn.Close() // ignore errors
				f.setStateError(ctx, peer, err)
				continue
			}
			f.setState(ctx, bgp.BGP_FSM_OPENSENT)

		case bgp.BGP_FSM_OPENSENT:
			collisionDetector = newCollisionDetector(connecting, f, peer, transportAFI, f.session.Logger)
			m, err := fsmRecvMessage(bgpConn, buf[:], time.Now().Add(defaultMessageTimeout))
			if err != nil {
				f.setStateError(ctx, peer, err)
				maybeSendNotification(bgpConn, err) // ignore errors
				bgpConn.Close()                     // ignore errors
				continue
			}
			switch o := m.Body.(type) {
			case *bgp.BGPOpen:
				sess, subcode, err := validateOpen(o, transportAFI, peer, f.server.logger())
				if err != nil {
					if subcode != 0 {
						fsmSendNotification(bgpConn, bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, subcode, nil) // ignore errors
					}
					f.setStateError(ctx, peer, err)
					bgpConn.Close() // ignore errors
					continue
				}
				// Replace the initial session with the one created by validateOpen.
				f.session = sess
				if err := fsmSendKeepAlive(bgpConn, f.timers.HoldTime); err != nil {
					f.setStateError(ctx, peer, err)
					bgpConn.Close() // ignore errors
					continue
				}
				holdTime = time.Duration(o.HoldTime) * time.Second
				f.setState(ctx, bgp.BGP_FSM_OPENCONFIRM)
			default:
				fsmSendNotification(bgpConn, bgp.BGP_ERROR_FSM_ERROR, bgp.BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_STATE, nil) // ignore errors
				f.setStateError(ctx, peer, fmt.Errorf("received unexpected message type %v", m.Header.Type))
				bgpConn.Close() // ignore errors
			}

		case bgp.BGP_FSM_OPENCONFIRM:
			m, err := fsmRecvMessage(bgpConn, buf[:], time.Now().Add(defaultMessageTimeout))
			if err != nil {
				f.setStateError(ctx, peer, err)
				maybeSendNotification(bgpConn, err) // ignore errors
				bgpConn.Close()                     // ignore errors
				continue
			}
			switch n := m.Body.(type) {
			case *bgp.BGPKeepAlive:
				f.setState(ctx, bgp.BGP_FSM_ESTABLISHED)
			case *bgp.BGPNotification:
				f.setStateError(ctx, peer, fmt.Errorf(
					"received notification code=%v subcode=%v data=%q",
					n.ErrorCode, n.ErrorSubcode, string(n.Data),
				))
				bgpConn.Close() // ignore errors
				continue
			default:
				fsmSendNotification(bgpConn, bgp.BGP_ERROR_FSM_ERROR, bgp.BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE, nil) // ignore errors
				f.setStateError(ctx, peer, fmt.Errorf("received unexpected message type %v", m.Header.Type))
				bgpConn.Close() // ignore errors
			}

		case bgp.BGP_FSM_ESTABLISHED:
			connectBackoff.Reset()
			f.session.initCache()
			f.session.setLocalIP(bgpConn)
			notifyC, sendErrC := f.sendLoop(ctx, bgpConn)
			recvErrC, recvDoneC := f.recvLoop(ctx, bgpConn, peer.Addr, peer.importFilter, holdTime, notifyC)
			f.session.RecvDone = recvDoneC
			select {
			case err := <-sendErrC:
				if err != nil {
					f.setStateError(ctx, peer, fmt.Errorf("send: %v", err))
				} else {
					// The error emitted by sendLoop should only be nil if a NOTIFICATION
					// was successfully sent. Handle the original error from recvLoop, but
					// don't block if there is none.
					select {
					case err := <-recvErrC:
						f.setStateError(ctx, peer, fmt.Errorf("receive: %v", err))
					default:
					}
				}
			case err := <-recvErrC:
				f.setStateError(ctx, peer, fmt.Errorf("receive: %v", err))
				select {
				// Wait for sendLoop to send an optional NOTIFICATION and terminate.
				case <-sendErrC:
				// But don't wait forever. (This case shouldn't happen if we're diligent
				// about signaling the sendLoop to shut down after any receive error.)
				case <-time.After(defaultNotificationTimeout):
				}
			case <-f.stopC:
				notifyC <- notification{bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET}
				f.setState(ctx, state_BGP_FSM_TERMINATE)
				select {
				// Wait for sendLoop to transmit the NOTIFICATION and terminate.
				case <-sendErrC:
				// But make sure that shutdown doesn't block forever.
				case <-time.After(10 * time.Second):
				}
			}
			bgpConn.Close() // ignore errors

		case state_BGP_FSM_ERROR:
			if f.session.RecvDone != nil {
				<-f.session.RecvDone // wait for receive loop to terminate
				f.removePaths(peer.Addr)
				f.session.Cleared = true
			}
			nextState := bgp.BGP_FSM_IDLE
			if peer.dynamic {
				nextState = state_BGP_FSM_TERMINATE
			}
			f.setState(ctx, nextState)

		case state_BGP_FSM_TERMINATE:
			if peer.dynamic {
				f.server.removeDynamicPeer(peer)
			}
			if f.session.RecvDone != nil && !f.session.Cleared {
				<-f.session.RecvDone // wait for receive loop to terminate
				f.removePaths(peer.Addr)
				f.session.Cleared = true
			}
			close(f.doneC)
			return

		default:
			panic("reached invalid state")
		}
	}
}

func (f *fsm) stop() {
	close(f.stopC)
	<-f.doneC
}
