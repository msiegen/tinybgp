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
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
)

// jsonString returns a printable string. It's used to display test output for
// types where the String method provides only a subset of the fields.
func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestDefaultImportFilter(t *testing.T) {
	fsm := &fsm{
		server: &Server{ASN: 65544},
	}
	for _, tc := range []struct {
		Name    string
		Peer    *Peer
		Attrs   Attributes
		Want    Attributes
		WantErr error
	}{
		{
			Name: "accept_matching_next_asn",
			Peer: &Peer{
				fsm: fsm,
				ASN: 65541,
			},
			Attrs: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65541, 65542, 65543})
				return a
			}(),
			Want: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65541, 65542, 65543})
				return a
			}(),
		},
		{
			Name: "reject_nonmatching_next_asn",
			Peer: &Peer{
				fsm: fsm,
				ASN: 65541,
			},
			Attrs: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65543, 65545, 65547})
				return a
			}(),
			WantErr: ErrDiscard,
		},
		{
			Name: "accept_any_next_asn",
			Peer: &Peer{
				fsm: fsm,
			},
			Attrs: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65541, 65542, 65543})
				return a
			}(),
			Want: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65541, 65542, 65543})
				return a
			}(),
		},
		{
			Name: "reject_own_asn",
			Peer: &Peer{
				fsm: fsm,
			},
			Attrs: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65543, 65544, 65545})
				return a
			}(),
			WantErr: ErrDiscard,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			nlri := netip.MustParsePrefix("2001:db8::/48")
			got := tc.Attrs
			err := tc.Peer.DefaultImportFilter(nlri, &got)
			if !errors.Is(err, tc.WantErr) {
				t.Fatalf("got error %v, want error %v", err, tc.WantErr)
			}
			if err != nil {
				return
			}
			if got != tc.Want {
				t.Errorf("\ngot:\n  %v\nwant:\n  %v", jsonString(got), jsonString(tc.Want))
			}
		})
	}
}

func TestDefaultExportFilter(t *testing.T) {
	fsm := &fsm{
		server:  &Server{ASN: 65544},
		session: session{LocalIP: netip.MustParseAddr("2001:db8::1")},
	}
	for _, tc := range []struct {
		Name    string
		Peer    *Peer
		Attrs   Attributes
		Want    Attributes
		WantErr error
	}{
		{
			Name: "discard_no_export",
			Peer: &Peer{fsm: fsm},
			Attrs: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65541, 65542, 65543})
				a.SetCommunities(map[Community]bool{
					Community{0xffff, 0xff01}: true, // no export
				})
				return a
			}(),
			WantErr: ErrDiscard,
		},
		{
			Name: "prepend_own_asn_and_set_nexthop",
			Peer: &Peer{fsm: fsm},
			Attrs: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65541, 65542, 65543})
				return a
			}(),
			Want: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65544, 65541, 65542, 65543})
				a.SetNexthop(netip.MustParseAddr("2001:db8::1"))
				return a
			}(),
		},
		{
			Name: "clear_med",
			Peer: &Peer{fsm: fsm},
			Attrs: Attributes{
				med:    42,
				hasMED: true,
			},
			Want: func() Attributes {
				var a Attributes
				a.SetPath([]uint32{65544})
				a.SetNexthop(netip.MustParseAddr("2001:db8::1"))
				return a
			}(),
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			nlri := netip.MustParsePrefix("2001:db8::/48")
			got := tc.Attrs
			err := tc.Peer.DefaultExportFilter(nlri, &got)
			if !errors.Is(err, tc.WantErr) {
				t.Fatalf("got error %v, want error %v", err, tc.WantErr)
			}
			if err != nil {
				return
			}
			if got != tc.Want {
				t.Errorf("\ngot:\n  %v\nwant:\n  %v", jsonString(got), jsonString(tc.Want))
			}
		})
	}
}
