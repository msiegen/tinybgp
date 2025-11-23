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
	"encoding/binary"
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

// ExtendedCommunity is a BGP Extended Community as defined in
// https://datatracker.ietf.org/doc/html/rfc4360.
//
// NOTE: Support for extended communities is experimental and subject to change.
// Extended communities are not widely used on the internet and several details
// of this implementation were determined empirically from a handful of routes.
// If you need this and are able to contribute either code or expertise, please
// open an issue on GitHub.
type ExtendedCommunity uint64

func newExtendedCommunity(b []byte) (ExtendedCommunity, error) {
	if len(b) != 8 {
		return 0, fmt.Errorf("invalid length for extended community: got %v, want 8", len(b))
	}
	return ExtendedCommunity(binary.BigEndian.Uint64(b)), nil
}

// type_ returns the high-order octet of the type field.
func (c ExtendedCommunity) type_() uint8 {
	return uint8(c >> 56) // & 0xff
}

// subType returns the low-order octet of the type field.
func (c ExtendedCommunity) subType() uint8 {
	return uint8(c >> 48) // & 0xff
}

// global returns the global administrator sub-field. It may be 2 bytes or
// 4 bytes depending on the value in the type field. If the length cannot be
// determined, a value of zero is returned.
func (c ExtendedCommunity) global() uint32 {
	switch c.type_() {
	case 0x00, 0x40:
		return uint32(c>>32) & 0xffff
	case 0x01, 0x02, 0x41:
		return uint32(c >> 16) // & 0xffffffff
	}
	return 0
}

// local returns the local administrator sub-field. It may be 2 bytes or
// 4 bytes depending on the value in the type field. If the length cannot be
// determined, a value of zero is returned.
func (c ExtendedCommunity) local() uint32 {
	switch c.type_() {
	case 0x00, 0x40:
		return uint32(c) // & 0xffffffff
	case 0x01, 0x02, 0x41:
		return uint32(c) & 0xffff
	}
	return 0
}

// String returns a human-readable string. The format is subject to change.
func (c ExtendedCommunity) String() string {
	switch c.subType() {
	case 0x02:
		switch c.type_() {
		case 0x00, 0x02:
			return fmt.Sprintf("rt:%v:%v", c.global(), c.local())
		}
	case 0x03:
		switch c.type_() {
		case 0x00, 0x02:
			return fmt.Sprintf("soo:%v:%v", c.global(), c.local())
		}
	}
	return fmt.Sprintf("%016x", uint64(c))
}

// LargeCommunity is a BGP large community as defined in
// https://datatracker.ietf.org/doc/html/rfc8092
type LargeCommunity struct {
	ASN, Data1, Data2 uint32
}

// ParseLargeCommunity parses a large community from a string like "64512:1:2".
func ParseLargeCommunity(c string) (LargeCommunity, error) {
	parts := strings.Split(c, ":")
	if len(parts) != 3 {
		return LargeCommunity{}, fmt.Errorf("large community is not three parts: %q", c)
	}
	asn, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return LargeCommunity{}, fmt.Errorf("invalid large community asn: %v", err)
	}
	data1, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return LargeCommunity{}, fmt.Errorf("invalid large community data 1: %v", err)
	}
	data2, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return LargeCommunity{}, fmt.Errorf("invalid large community data 2: %v", err)
	}
	return LargeCommunity{uint32(asn), uint32(data1), uint32(data2)}, nil
}

// String converts a community to a colon separated string like "64512:1:2".
func (c LargeCommunity) String() string {
	return fmt.Sprintf("%v:%v:%v", c.ASN, c.Data1, c.Data2)
}

// LessThan returns whether a sorts ahead of b.
func (a LargeCommunity) LessThan(b LargeCommunity) bool {
	switch {
	case a.ASN < b.ASN:
		return true
	case a.ASN > b.ASN:
		return false
	default:
		switch {
		case a.Data1 < b.Data1:
			return true
		case a.Data1 > b.Data1:
			return false
		default:
			return a.Data2 < b.Data2
		}
	}
}
