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
	"strconv"
	"strings"
)

// Community is a BGP community as defined in
// https://datatracker.ietf.org/doc/html/rfc1997.
type Community struct {
	Origin uint16
	Value  uint16
}

// NewCommunity creates a community from its numeric representation.
func NewCommunity(c uint32) Community {
	return Community{uint16(c >> 16), uint16(c & 0xffff)}
}

// ParseCommunity parses a community from a string like "64512:1".
func ParseCommunity(c string) (Community, error) {
	parts := strings.Split(c, ":")
	if len(parts) != 2 {
		return Community{}, fmt.Errorf("community is not two parts: %q", c)
	}
	origin, err := strconv.Atoi(parts[0])
	if err != nil {
		return Community{}, fmt.Errorf("invalid community origin: %v", err)
	}
	if origin < 0 || origin > 0xffff {
		return Community{}, fmt.Errorf("invalid community origin: out of range: %v", origin)
	}
	value, err := strconv.Atoi(parts[1])
	if err != nil {
		return Community{}, fmt.Errorf("invalid community value: %v", err)
	}
	if value < 0 || value > 0xffff {
		return Community{}, fmt.Errorf("invalid community value: out of range: %v", value)
	}
	return Community{uint16(origin), uint16(value)}, nil
}

// Uint32 converts a community to its numeric representation.
func (c Community) Uint32() uint32 {
	return uint32(c.Origin)<<16 | uint32(c.Value)
}

// String converts a community to a colon separated string like "64512:1".
func (c Community) String() string {
	return fmt.Sprintf("%v:%v", c.Origin, c.Value)
}
