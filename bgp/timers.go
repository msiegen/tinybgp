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
	"math/rand"
	"time"
)

const (
	// defaultHoldTime is how long the remote end should hold the session if we
	// stop sending KEEPALIVEs. Per the BGP spec this must be at least 3 seconds.
	defaultHoldTime = 90 * time.Second
	// defaultKeepAliveInterval and defaultKeepAliveFuzz specify how often we send
	// KEEPALIVEs.
	defaultKeepAliveInterval = 27 * time.Second
	defaultKeepAliveFuzz     = 2 * time.Second
	// defaultOpenTimeout is the timeout to dial the peer and transmit an OPEN.
	defaultOpenTimeout = 10 * time.Second
	// defaultMessageTimeout is the timeout for most messages sent and received.
	defaultMessageTimeout = 30 * time.Second
	// defaultNotificationTimeout is the transmit timeout for NOTIFICATIONs.
	defaultNotificationTimeout = 3 * time.Second
)

type Timers struct {
	HoldTime          time.Duration
	KeepAliveInterval time.Duration
	KeepAliveFuzz     time.Duration
}

func newTimers(from *Timers) *Timers {
	t := &Timers{
		HoldTime:          defaultHoldTime,
		KeepAliveInterval: defaultKeepAliveInterval,
		KeepAliveFuzz:     defaultKeepAliveFuzz,
	}
	if from != nil {
		if from.HoldTime != 0 {
			t.HoldTime = from.HoldTime
		}
		if from.KeepAliveInterval != 0 {
			t.KeepAliveInterval = from.KeepAliveInterval
			t.KeepAliveFuzz = from.KeepAliveFuzz
		}
	}
	return t
}

func (t *Timers) NextKeepAlive() time.Duration {
	if t.KeepAliveFuzz == 0 {
		return t.KeepAliveInterval
	}
	return t.KeepAliveInterval + time.Duration(rand.Int63n(int64(t.KeepAliveFuzz)))
}
