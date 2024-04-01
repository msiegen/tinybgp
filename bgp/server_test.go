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
	"net"
	"net/netip"
	"testing"
	"time"
)

// logger implements the Logger interface for use in testing.
type logger struct {
	t      *testing.T
	prefix string
}

func (l *logger) Printf(fmt string, args ...any) {
	l.t.Logf(l.prefix+fmt, args...)
}

func newLogger(t *testing.T, prefix string) *logger {
	return &logger{t, prefix}
}

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
	} {
		t.Run(tc.Name, func(t *testing.T) {
			// Enable debug logging.
			tc.LeftServer.Logger = newLogger(t, "L: ")
			tc.RightServer.Logger = newLogger(t, "R: ")

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
					t.Errorf("L: server failed: %v", err)
				}
			}()
			defer tc.LeftServer.Close()
			go func() {
				if err := tc.RightServer.Serve(rightListener); err != nil {
					t.Errorf("R: server failed: %v", err)
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
