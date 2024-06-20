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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// A Logger writes lines of output for debug purposes.
type Logger interface {
	Printf(string, ...any)
}

// Server is a BGP server.
type Server struct {
	// Hostname is the server's short name. If present, it will be announced to
	// peers via the FQDN capability.
	Hostname string
	// Domainname is the server's domain. If present, it will be announced to
	// peers via the FQDN capability.
	Domainname string
	// RouterID is a unique identifier for this router within its AS. You must
	// populate this with a 32-bit number formatted as an IPv4 address.
	RouterID string
	// ASN is the autonomous system number. This is required.
	ASN uint32
	// CreatePeer is called when an incomming connection doesn't match any
	// predefined peer. If this function is non-nil and returns a non-error, the
	// connection will be accepted using the dynamically created peer. Dynamic
	// peers are destroyed when their TCP connection is closed.
	CreatePeer func(localAddr, remoteAddr netip.Addr, conn net.Conn) (*Peer, error)
	// Logger is the destination for human readable debug logs. If you want logs,
	// you need to set this. To use standard Go logging set it to log.Default().
	Logger Logger

	mu           sync.Mutex
	listeners    []net.Listener
	peers        map[netip.Addr]*Peer
	dynamicPeers map[*Peer]struct{}
	running      bool
	closed       bool
	serverClosed chan struct{}
	peersStopped chan struct{}
}

func (s *Server) logf(format string, v ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, v...)
	}
}

func (s *Server) fatalf(format string, v ...any) {
	if logger, ok := s.Logger.(interface{ Fatalf(string, ...any) }); ok {
		logger.Fatalf(format, v...)
	}
	s.logf(format, v...)
	panic(fmt.Sprintf(format, v...))
}

func (s *Server) startPeer(p *Peer) error {
	// invariant: s.mu is locked
	if p.ConfigureListener != nil {
		for _, l := range s.listeners {
			if err := p.ConfigureListener(l); err != nil {
				return err
			}
		}
	}
	return p.start(s)
}

// AddPeer adds a peer.
//
// Peers that are added to a non-running server will be held idle until Serve
// is called. Peers that are added after the first call to Serve will
// immediately have their state machine start running.
func (s *Server) AddPeer(p *Peer) error {
	if !p.Addr.IsValid() {
		return fmt.Errorf("invalid peer address: %v", p.Addr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("cannot add peer to closed server")
	}
	if s.peers[p.Addr] != nil {
		return fmt.Errorf("duplicate peer: %v", p.Addr)
	}
	if s.peers == nil {
		s.peers = map[netip.Addr]*Peer{}
	}
	s.peers[p.Addr] = p
	if s.running {
		return s.startPeer(p)
	}
	return nil
}

// RemovePeer removes a peer.
func (s *Server) RemovePeer(peer netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("cannot remove peer from closed server")
	}
	p := s.peers[peer]
	if p == nil {
		return fmt.Errorf("peer not found: %v", peer)
	}
	p.stop()
	delete(s.peers, peer)
	return nil
}

func (s *Server) removeDynamicPeer(p *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dynamicPeers, p)
}

func (s *Server) matchPeer(conn net.Conn) (*Peer, error) {
	localAddr, _ := addrFromNetAddr(conn.LocalAddr())
	remoteAddr, remotePort := addrFromNetAddr(conn.RemoteAddr())
	if !localAddr.IsValid() || !remoteAddr.IsValid() {
		return nil, errors.New("unsupported peer address type")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var (
		fullMatch   []*Peer
		remoteMatch []*Peer
		localMatch  []*Peer
	)
	for _, p := range s.peers {
		switch {
		case remoteAddr == p.Addr && localAddr == p.LocalAddr:
			fullMatch = append(fullMatch, p)
		case remoteAddr == p.Addr && !p.LocalAddr.IsValid():
			remoteMatch = append(remoteMatch, p)
		case localAddr == p.LocalAddr && !p.Addr.IsValid():
			localMatch = append(localMatch, p)
		}
	}
	for _, match := range [][]*Peer{fullMatch, remoteMatch, localMatch} {
		switch len(match) {
		case 1:
			return match[0], nil
		case 0:
			continue
		default:
			return nil, errors.New("ambiguous match of more than one peer")
		}
	}
	if s.CreatePeer == nil {
		return nil, errors.New("unknown peer")
	}
	p, err := s.CreatePeer(localAddr, remoteAddr, conn)
	if err != nil {
		return nil, err
	}
	p.Addr = remoteAddr
	p.Port = remotePort
	p.Passive = true
	p.LocalAddr = localAddr
	p.dynamic = true
	p.start(s)
	s.dynamicPeers[p] = struct{}{}
	return p, nil
}

func (s *Server) acceptLoop(l net.Listener) error {
	defer s.Close() // close server if any listener fails
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept on %v: %v", l.Addr(), err)
		}
		p, err := s.matchPeer(conn)
		if err != nil {
			s.logf("Rejecting connection from %v: %v", conn.RemoteAddr(), err)
			conn.Close() // ignore errors
			continue
		}
		select {
		case p.fsm.acceptC <- conn:
			// We've successfully handed off the connection to the FSM!
		default:
			// The FSM's input queue is full; immediately close the connection so that
			// we don't block the accept loop. This can happen if the peer tries to
			// open two connections. It will never happen for dynamic peers because
			// those are created per-connection with an acceptC buffer size of 1.
			s.logf("Rejecting connection from %v: peer queue is full", conn.RemoteAddr(), err)
			conn.Close() // ignore errors
		}
	}
}

func (s *Server) start(l net.Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("cannot start a closed server")
	}
	if l != nil {
		s.listeners = append(s.listeners, l)
	}
	if s.running {
		for _, p := range s.peers {
			if p.ConfigureListener != nil {
				if err := p.ConfigureListener(l); err != nil {
					return err
				}
			}
		}
		return nil
	}
	s.running = true
	s.dynamicPeers = map[*Peer]struct{}{}
	s.serverClosed = make(chan struct{})
	s.peersStopped = make(chan struct{})
	for _, p := range s.peers {
		if err := s.startPeer(p); err != nil {
			return err
		}
	}
	return nil
}

// Serve runs the BGP protocol. A listener is optional, and multiple listeners
// can be provided by calling Serve concurrently in several goroutines. All
// concurrent calls to Serve block until a single call to Shutdown or Close is
// made.
func (s *Server) Serve(l net.Listener) error {
	if err := s.start(l); err != nil {
		return err
	}
	if l != nil {
		return s.acceptLoop(l)
	}
	<-s.serverClosed
	return errors.New("server closed")
}

// Shutdown terminates the server and closes all listeners. It waits for all
// peering connections to be closed before returning.
func (s *Server) Shutdown(ctx context.Context) error {
	s.Close() // ignore errors
	select {
	case <-s.peersStopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close terminates the server and closes all listeners. It does not wait for
// peering connections to be closed; to do that call Shutdown instead.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Only invoke the close sequence once.
	if s.closed {
		return errors.New("server is already closed")
	}
	s.closed = true
	close(s.serverClosed)

	// Close all listeners.
	var closeErr error
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			// Only keep the first error from any listener.
			if closeErr == nil {
				closeErr = err
			}
		}
	}

	// Stop the peers, but don't wait for them.
	go func() {
		var wg sync.WaitGroup
		for _, p := range s.peers {
			wg.Add(1)
			go func(p *Peer) {
				p.stop()
				wg.Done()
			}(p)
		}
		wg.Wait()
		close(s.peersStopped)
	}()

	return closeErr
}
