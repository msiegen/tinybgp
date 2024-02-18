// This file is derived from pkg/server/sockopt_linux.go in
// https://github.com/osrg/gobgp. Original copyright follows.
//
// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//go:build linux
// +build linux

package tcpmd5

import (
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func buildTcpMD5Sig(address, key string) *unix.TCPMD5Sig {
	t := unix.TCPMD5Sig{}
	addr := net.ParseIP(address)
	if addr.To4() != nil {
		t.Addr.Family = unix.AF_INET
		copy(t.Addr.Data[2:], addr.To4())
	} else {
		t.Addr.Family = unix.AF_INET6
		copy(t.Addr.Data[6:], addr.To16())
	}

	t.Keylen = uint16(len(key))
	copy(t.Key[0:], []byte(key))

	return &t
}

// DialerControl returns a function that enables TCP MD5 signatures on dialed
// connections. See https://pkg.go.dev/net#Dialer.Control for details.
func DialerControl(password string) func(_, _ string, _ syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var sockerr error
		if password != "" {
			addr, _, _ := net.SplitHostPort(address)
			t := buildTcpMD5Sig(addr, password)
			if err := c.Control(func(fd uintptr) {
				sockerr = os.NewSyscallError("setsockopt", unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG, t))
			}); err != nil {
				return err
			}
			if sockerr != nil {
				return sockerr
			}
		}
		return nil
	}
}
