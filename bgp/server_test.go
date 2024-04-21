// Copyright 2024 Google LLC
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
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/msiegen/tinybgp/third_party/tcpmd5"
)

// logger implements the Logger interface for use in testing.
type logger struct {
	t       *testing.T
	started time.Time
	prefix  string

	mu   sync.Mutex
	done bool
}

func (l *logger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done {
		ts := fmt.Sprintf("%03.6f", float64(time.Since(l.started).Nanoseconds())/1e9)
		l.t.Logf(ts+" "+l.prefix+format, args...)
	}
}

func (l *logger) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.done = true
}

func newLogger(t *testing.T, started time.Time, prefix string) *logger {
	return &logger{
		t:       t,
		started: started,
		prefix:  prefix,
	}
}

// TestServer may exercise varied code paths depending on timing. To run a
// single subtest multiple times in sequence, invoke it like this:
//
//	go test -v -count=10 ./... --test.run=TestServer/both_sides_active
func TestServer(t *testing.T) {
	loopback := netip.MustParseAddr("::1")

	for _, tc := range []struct {
		Name        string
		LeftServer  *Server
		LeftPeer    *Peer
		RightServer *Server
		RightPeer   *Peer
	}{
		{
			Name: "one_side_passive",
			LeftServer: &Server{
				RouterID: "100.64.0.1",
				ASN:      64521,
			},
			LeftPeer: &Peer{
				ASN:     64522,
				Passive: true,
				Export:  map[RouteFamily]*Table{IPv6Unicast: &Table{}},
			},
			RightServer: &Server{
				RouterID: "100.64.0.2",
				ASN:      64522,
			},
			RightPeer: &Peer{
				ASN:    64521,
				Import: map[RouteFamily]*Table{IPv6Unicast: &Table{}},
			},
		},
		{
			Name: "both_sides_active",
			LeftServer: &Server{
				RouterID: "100.64.0.1",
				ASN:      64521,
			},
			LeftPeer: &Peer{
				ASN:    64522,
				Export: map[RouteFamily]*Table{IPv6Unicast: &Table{}},
			},
			RightServer: &Server{
				RouterID: "100.64.0.2",
				ASN:      64522,
			},
			RightPeer: &Peer{
				ASN:    64521,
				Import: map[RouteFamily]*Table{IPv6Unicast: &Table{}},
			},
		},
		{
			Name: "both_sides_active_collision_detection_reversed",
			LeftServer: &Server{
				RouterID: "100.64.0.3",
				ASN:      64523,
			},
			LeftPeer: &Peer{
				ASN:    64522,
				Export: map[RouteFamily]*Table{IPv6Unicast: &Table{}},
			},
			RightServer: &Server{
				RouterID: "100.64.0.2",
				ASN:      64522,
			},
			RightPeer: &Peer{
				ASN:    64523,
				Import: map[RouteFamily]*Table{IPv6Unicast: &Table{}},
			},
		},
		{
			Name: "md5_auth",
			LeftServer: &Server{
				RouterID: "100.64.0.1",
				ASN:      64521,
			},
			LeftPeer: &Peer{
				ASN:           64522,
				Export:        map[RouteFamily]*Table{IPv6Unicast: &Table{}},
				DialerControl: tcpmd5.DialerControl("hunter2"),
			},
			RightServer: &Server{
				RouterID: "100.64.0.2",
				ASN:      64522,
			},
			RightPeer: &Peer{
				ASN:               64521,
				Passive:           true,
				Import:            map[RouteFamily]*Table{IPv6Unicast: &Table{}},
				ConfigureListener: tcpmd5.ConfigureListener("::1", "hunter2"),
			},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			tc := tc
			t.Parallel()

			testStarted := time.Now()
			// Enable debug logging.
			leftLogger := newLogger(t, testStarted, "L: ")
			defer leftLogger.Stop()
			tc.LeftServer.Logger = leftLogger
			rightLogger := newLogger(t, testStarted, "R: ")
			defer rightLogger.Stop()
			tc.RightServer.Logger = rightLogger

			// Start two listeners on any available ports.
			leftListener, err := net.Listen("tcp", "[::1]:0")
			if err != nil {
				t.Fatalf("L: failed to listen: %v", err)
			}
			rightListener, err := net.Listen("tcp", "[::1]:0")
			if err != nil {
				t.Fatalf("R: failed to listen: %v", err)
			}

			// Configure the peer addresses.
			tc.LeftPeer.Addr = loopback
			tc.LeftPeer.Port = rightListener.Addr().(*net.TCPAddr).Port
			tc.RightPeer.Addr = loopback
			tc.RightPeer.Port = leftListener.Addr().(*net.TCPAddr).Port

			// Tell each server where to find its peer.
			if err := tc.LeftServer.AddPeer(tc.LeftPeer); err != nil {
				t.Fatalf("L: failed to add peer: %v", err)
			}
			if err := tc.RightServer.AddPeer(tc.RightPeer); err != nil {
				t.Fatalf("R: failed to add peer: %v", err)
			}

			// Start the servers.
			go func() {
				if err := tc.LeftServer.Serve(leftListener); err != nil {
					leftLogger.Printf("server failed: %v", err)
				}
			}()
			defer tc.LeftServer.Close()
			go func() {
				if err := tc.RightServer.Serve(rightListener); err != nil {
					rightLogger.Printf("server failed: %v", err)
				}
			}()
			defer tc.RightServer.Close()

			// Export one path from the left server.
			wantPrefix := netip.MustParsePrefix("2001:db8:1::/48")
			tc.LeftPeer.Export[IPv6Unicast].Network(wantPrefix).AddPath(Path{})

			// Watch the right server until the path is received.
			started := time.Now()
			for i := 0; i < 30; i++ {
				time.Sleep(1 * time.Second)
				for _, gotPrefix := range tc.RightPeer.Import[IPv6Unicast].Prefixes() {
					t.Logf("Right server received prefix %v from left server", gotPrefix)
					if gotPrefix == wantPrefix {
						// Success!
						return
					}
				}
			}
			t.Errorf("Right server still did not get prefix %v from left server after %v", wantPrefix, time.Since(started))
		})
	}
}
