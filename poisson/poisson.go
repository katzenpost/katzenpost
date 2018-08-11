// timer.go - Poisson timer.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package poisson

import (
	"math"
	mrand "math/rand"
	"time"

	"github.com/katzenpost/core/crypto/rand"
)

// PoissonDescriptor describes a Poisson process.
type PoissonDescriptor struct {
	Lambda float64
	Shift  uint64
	Max    uint64
}

// Equals return true if the given PoissonDescriptor s is
// equal to d.
func (d *PoissonDescriptor) Equals(s *PoissonDescriptor) bool {
	if d.Lambda != s.Lambda {
		return false
	}
	if d.Shift != s.Shift {
		return false
	}
	if d.Max != s.Max {
		return false
	}
	return true
}

// PoissonTimer is used to produce channel events after delays
// selected from a Poisson process.
type PoissonTimer struct {
	Timer *time.Timer
	rng   *mrand.Rand
	desc  *PoissonDescriptor
}

// DescriptorEquals returns true if the PoissonTimer's Poisson descriptor
// is equal to the given Poisson descriptor s.
func (t *PoissonTimer) DescriptorEquals(s *PoissonDescriptor) bool {
	return t.desc.Equals(s)
}

// SetPoisson sets a new Poisson descriptor.
func (t *PoissonTimer) SetPoisson(desc *PoissonDescriptor) {
	t.desc = desc
}

func (t *PoissonTimer) nextInterval() time.Duration {
	wakeMsec := uint64(rand.Exp(t.rng, t.desc.Lambda))
	switch {
	case wakeMsec > t.desc.Max:
		wakeMsec = t.desc.Max
	default:
	}
	wakeMsec += t.desc.Shift // Sample, clamp, then shift.
	wakeInterval := time.Duration(wakeMsec) * time.Millisecond
	return wakeInterval
}

// Next resets the timer to the next Poisson process value.
// This MUST NOT be called unless the timer has fired.
func (t *PoissonTimer) Next() {
	wakeInterval := t.nextInterval()
	t.Timer.Reset(wakeInterval)
}

// NextMax resets the timer to the maximum
// possible value.
func (t *PoissonTimer) NextMax() {
	t.Timer.Reset(math.MaxInt64)
}

// Start is used to initialize and start the timer
// after timer creation.
func (t *PoissonTimer) Start() {
	wakeInterval := t.nextInterval()
	t.Timer = time.NewTimer(wakeInterval)
}

// Stop stops the timer.
func (t *PoissonTimer) Stop() {
	t.Timer.Stop()
}

// NewTimer is used to create a new PoissonTimer. A subsequent
// call to the Start method is used to activate the timer.
func NewTimer(desc *PoissonDescriptor) *PoissonTimer {
	t := &PoissonTimer{
		rng:  rand.NewMath(),
		desc: desc,
	}
	return t
}
