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
	peers        []*Peer
	dynamicPeers map[*Peer]struct{}
	running      bool
	stopC, doneC chan struct{}
	stopped      bool
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

// AddPeer adds a peer.
//
// Peers that are added to a non-running server will be held idle until Serve
// is called. Peers that are added after the first call to Serve will
// immediately have their state machine start running.
func (s *Server) AddPeer(p *Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errors.New("server has been stopped")
	}
	s.peers = append(s.peers, p)
	if s.running {
		p.start(s)
	}
	return nil
}

func (s *Server) removeDynamicPeer(p *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.dynamicPeers, p)
}

func (s *Server) matchPeer(conn net.Conn) (*Peer, error) {
	localAddr := addrFromNetAddr(conn.LocalAddr())
	remoteAddr := addrFromNetAddr(conn.RemoteAddr())
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
	p.Passive = true
	p.LocalAddr = localAddr
	p.dynamic = true
	p.start(s)
	s.dynamicPeers[p] = struct{}{}
	return p, nil
}

func (s *Server) acceptLoop(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.logf("Failed to accept connection on %v: %v", l.Addr(), err)
			s.Close() // ignore errors
			return
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

// Serve runs the BGP protocol. A listener is optional, and multiple listeners
// can be provided by calling Serve concurrently in several goroutines. All
// concurrent calls to Serve block until a single call to Shutdown or Close is
// made.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.running {
		if l != nil {
			s.listeners = append(s.listeners, l)
			go s.acceptLoop(l)
		}
		s.mu.Unlock()
		<-s.doneC
		return nil
	}
	s.running = true
	s.dynamicPeers = map[*Peer]struct{}{}
	s.stopC = make(chan struct{})
	s.doneC = make(chan struct{})
	for _, p := range s.peers {
		p.start(s)
	}
	if l != nil {
		s.listeners = append(s.listeners, l)
		go s.acceptLoop(l)
	}
	s.mu.Unlock()
	<-s.stopC
	var wg sync.WaitGroup
	for _, p := range s.peers {
		wg.Add(1)
		go func(p *Peer) {
			p.stop()
			wg.Done()
		}(p)
	}
	wg.Wait()
	close(s.doneC)
	return nil
}

// Shutdown terminates the server and closes all listeners. It waits for all
// peering connections to be closed before returning.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.Close(); err != nil {
		return err
	}
	select {
	case <-s.doneC:
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
	if s.stopC == nil {
		return errors.New("server is not running")
	}
	if s.stopped {
		return errors.New("server is already closed")
	}
	for _, l := range s.listeners {
		l.Close() // ignore errors
	}
	close(s.stopC)
	s.stopped = true
	return nil
}
