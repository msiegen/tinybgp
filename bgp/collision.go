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
	"log/slog"
	"net"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// collisionDetector runs a simplified BGP state machine in the background that
// accepts an incomming connection while the main state machine is occupied by
// dialing an outgoing connection to the same peer. It applies the rules in
// https://datatracker.ietf.org/doc/html/rfc4271#section-6.8 and
// https://datatracker.ietf.org/doc/html/rfc6286#section-2.3 to decide which
// connection is preferred.
//
// If the locally initiated connection is preferred, collisionDetector closes
// the incomming one with a notification code of CEASE and subcode of
// SUB_CONNECTION_COLLISION_RESOLUTION.
//
// If the incomming connection is preferred, collisionDetector holds it for a
// short time. The remote end will also detect the collision and close the
// connection it accepted. This unblocks the local state machine so that it can
// pick up the connection being held by collisionDetector.
type collisionDetector struct {
	connC   chan net.Conn
	doneC   chan bool
	session session
}

func newCollisionDetector(connecting bool, f *fsm, peer *Peer, transportAFI uint16, earlyLogger *slog.Logger) *collisionDetector {
	if !connecting {
		// If we haven't tried to initiate a connection ourselves, then no
		// possibility of a collision exists.
		return nil
	}
	d := &collisionDetector{
		connC: make(chan net.Conn),
		doneC: make(chan bool),
	}
	go d.run(f, peer, transportAFI, earlyLogger)
	return d
}

func ipToRouterID(ip net.IP) uint32 {
	ip = ip.To4()
	if len(ip) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func stringToRouterID(s string) uint32 {
	return ipToRouterID(net.ParseIP(s))
}

func (d *collisionDetector) run(f *fsm, peer *Peer, transportAFI uint16, earlyLogger *slog.Logger) {
	// Until we receive an OPEN message from the peer, not all fields for the
	// structured logger are available. Use a logger with fewer fields.
	l := earlyLogger

	select {
	case c := <-f.acceptC:
		// Send OPEN message.
		if err := f.sendOpen(c, transportAFI); err != nil {
			c.Close() // ignore errors
			l.Error("collision detector failed to send open", "details", err)
			return
		}

		// Wait for OPEN message from the peer.
		m, err := fsmRecvMessage(c, time.Now().Add(defaultMessageTimeout))
		if err != nil {
			maybeSendNotification(c, err) // ignore errors
			c.Close()                     // ignore errors
			l.Error("collision detector failed to receive open", "details", err)
			return
		}

		// Validate the OPEN message from the peer.
		o, ok := m.Body.(*bgp.BGPOpen)
		if !ok {
			code := uint8(bgp.BGP_ERROR_FSM_ERROR)
			subcode := uint8(bgp.BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_STATE)
			fsmSendNotification(c, code, subcode, nil) // ignore errors
			c.Close()                                  // ignore errors
			l.Error("collision detector received unexpected message type while waiting for open")
			return
		}
		sess, code, err := validateOpen(o, transportAFI, peer, f.server.logger())
		if err != nil {
			if code != 0 {
				fsmSendNotification(c, bgp.BGP_ERROR_OPEN_MESSAGE_ERROR, code, nil) // ignore errors
			}
			c.Close() // ignore errors
			l.Error("collision detector received invalid open", "details", err)
			return
		}

		// We should now have a full logger that populates additional attributes
		// parsed out of the peer's OPEN message. Use it instead of earlyLogger.
		l = sess.Logger

		// Send KEEPALIVE message.
		if err := fsmSendKeepAlive(c, f.timers.HoldTime); err != nil {
			c.Close() // ignore errors
			l.Error("collision detector failed to send keepalive", "details", err)
			return
		}

		// Wait for KEEPALIVE from the peer.
		m, err = fsmRecvMessage(c, time.Now().Add(defaultMessageTimeout))
		if err != nil {
			maybeSendNotification(c, err) // ignore errors
			c.Close()                     // ignore errors
			l.Error("collision detector failed to receive keepalive", "details", err)
			return
		}

		// Validate the KEEPALIVE from the peer.
		_, ok = m.Body.(*bgp.BGPKeepAlive)
		if !ok {
			code := uint8(bgp.BGP_ERROR_FSM_ERROR)
			subcode := uint8(bgp.BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE)
			fsmSendNotification(c, code, subcode, nil) // ignore errors
			c.Close()                                  // ignore errors
			l.Error("collision detector received unexpected message type while waiting for keepalive")
			return
		}

		peerID := ipToRouterID(o.ID)
		localID := stringToRouterID(f.server.RouterID)
		peerASN := sess.PeerASN
		localASN := f.server.ASN

		if peerID < localID || (peerID == localID && peerASN < localASN) {
			// Prefer the locally initiated connection that is being handled in the
			// main FSM, not the peer connection here in the collision detector.
			code := uint8(bgp.BGP_ERROR_CEASE)
			subcode := uint8(bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION)
			fsmSendNotification(c, code, subcode, nil) // ignore errors
			c.Close()                                  // ignore errors
			l.Info("closed colliding connection")
			return
		}

		d.session = sess

		select {
		case d.connC <- c:
			// Successfully passed the connection to the main state machine.
		case <-time.After(defaultMessageTimeout):
			// The state machine wasn't ready in time. Close the connection.
			fsmSendNotification(c, bgp.BGP_ERROR_FSM_ERROR, bgp.BGP_ERROR_SUB_OUT_OF_RESOURCES, nil) // ignore errors
			c.Close()                                                                                // ignore errors
			return
		}

	case <-d.doneC:
	}
}

// Chan returns a channel for getting the connection accepted by the
// collisionDetector.
func (h *collisionDetector) Chan() <-chan net.Conn {
	if h == nil {
		return nil
	}
	return h.connC
}

// Stop stops the collisionDetector.
func (h *collisionDetector) Stop() {
	if h != nil {
		close(h.doneC)
	}
}
