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

import "testing"

func TestNewCommunity(t *testing.T) {
	for _, tc := range []struct {
		Name       string
		Input      uint32
		WantOrigin uint16
		WantValue  uint16
	}{
		{
			Name:       "all ones",
			Input:      0xffffffff,
			WantOrigin: 0xffff,
			WantValue:  0xffff,
		},
		{
			Name:       "leading ones",
			Input:      0xf123f456,
			WantOrigin: 0xf123,
			WantValue:  0xf456,
		},
		{
			Name:       "leading zeros",
			Input:      0x1230456,
			WantOrigin: 0x123,
			WantValue:  0x456,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			got := NewCommunity(tc.Input)
			if got.Origin != tc.WantOrigin {
				t.Errorf("origin: got 0x%x, want 0x%x", got.Origin, tc.WantOrigin)
			}
			if got.Value != tc.WantValue {
				t.Errorf("value: got 0x%x, want 0x%x", got.Value, tc.WantValue)
			}
			gotUint32 := got.Uint32()
			if gotUint32 != tc.Input {
				t.Errorf("Uint32(): got 0x%x, want 0x%x", gotUint32, tc.Input)
			}
		})
	}
}

func TestCommunityString(t *testing.T) {
	for _, tc := range []struct {
		Input string
		Want  Community
	}{
		{
			Input: "64512:1",
			Want:  Community{64512, 1},
		},
		{
			Input: "65535:65281",
			Want:  Community{0xffff, 0xff01},
		},
	} {
		t.Run(tc.Input, func(t *testing.T) {
			got, err := ParseCommunity(tc.Input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.Want {
				t.Errorf("got %v, want %v", got, tc.Want)
			}
			gotString := got.String()
			if gotString != tc.Input {
				t.Errorf("got %v, want %v", gotString, tc.Input)
			}
		})
	}
}

func TestCommunityStringError(t *testing.T) {
	for _, tc := range []string{
		"",
		"1234",
		"101202:456",
		"123:404505",
		"123:456:789",
	} {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseCommunity(tc)
			if err == nil {
				t.Fatal("got success, want error")
			}
		})
	}
}

func TestExtendedCommunity(t *testing.T) {
	for _, tc := range []struct {
		Input      []byte
		Want       ExtendedCommunity
		WantString string
	}{
		{
			Input:      []byte{0x02, 0x02, 0x00, 0x01, 0xe2, 0x40, 0x03, 0xe9},
			Want:       0x02020001e24003e9,
			WantString: "rt:123456:1001",
		},
		{
			Input:      []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x55, 0x77},
			Want:       0x0003000000005577,
			WantString: "soo:0:21879",
		},
	} {
		t.Run(tc.WantString, func(t *testing.T) {
			c, err := newExtendedCommunity(tc.Input)
			if err != nil {
				t.Fatal(err)
			}
			if c != tc.Want {
				t.Errorf("got value %16x, want %16x", c, tc.Want)
			}
			if got := c.String(); got != tc.WantString {
				t.Errorf("got string %v, want %v", got, tc.WantString)
			}
		})
	}
}
