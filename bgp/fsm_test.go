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
	"testing"
)

func TestTwoByteASN(t *testing.T) {
	for _, tc := range []struct {
		Name    string
		Input   uint32
		Want    uint16
		WantErr bool
	}{
		{
			Name:  "public 2-byte",
			Input: 1234,
			Want:  1234,
		},
		{
			Name:  "private 2-byte",
			Input: 64512,
			Want:  64512,
		},
		{
			Name:  "public 4-byte",
			Input: 123456,
			Want:  23456,
		},
		{
			Name:  "private 4-byte",
			Input: 4200000000,
			Want:  23456,
		},
		{
			Name:    "invalid 2-byte",
			Input:   0,
			WantErr: true,
		},
		{
			Name:    "invalid 4-byte",
			Input:   4294967295,
			WantErr: true,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := twoByteASN(tc.Input)
			if tc.WantErr {
				if err == nil {
					t.Fatalf("got success, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("got error %q, want success", err)
			}
			if got != tc.Want {
				t.Errorf("got %v, want %v", got, tc.Want)
			}
		})
	}
}
