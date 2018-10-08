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

// Descriptor describes a Poisson process.
type Descriptor struct {
	Lambda float64
	Max    uint64
}

// Equals return true if the given Descriptor s is
// equal to d.
func (d *Descriptor) Equals(s *Descriptor) bool {
	if d.Lambda != s.Lambda {
		return false
	}
	if d.Max != s.Max {
		return false
	}
	return true
}

// Fount is used to produce channel events after delays
// selected from a Poisson process.
type Fount struct {
	Timer *time.Timer
	rng   *mrand.Rand
	desc  *Descriptor
}

// DescriptorEquals returns true if the Fount's Poisson descriptor
// is equal to the given Poisson descriptor s.
func (t *Fount) DescriptorEquals(s *Descriptor) bool {
	return t.desc.Equals(s)
}

// SetPoisson sets a new Poisson descriptor.
func (t *Fount) SetPoisson(desc *Descriptor) {
	t.desc = desc
}

func (t *Fount) nextInterval() time.Duration {
	wakeMsec := uint64(rand.Exp(t.rng, t.desc.Lambda))
	switch {
	case wakeMsec > t.desc.Max:
		wakeMsec = t.desc.Max
	default:
	}
	wakeInterval := time.Duration(wakeMsec) * time.Millisecond
	return wakeInterval
}

// Next resets the timer to the next Poisson process value.
// This MUST NOT be called unless the timer has fired.
func (t *Fount) Next() {
	wakeInterval := t.nextInterval()
	t.Timer.Reset(wakeInterval)
}

// NextMax resets the timer to the maximum
// possible value.
func (t *Fount) NextMax() {
	t.Timer.Reset(math.MaxInt64)
}

// Start is used to initialize and start the timer
// after timer creation.
func (t *Fount) Start() {
	wakeInterval := t.nextInterval()
	t.Timer = time.NewTimer(wakeInterval)
}

// Stop stops the timer.
func (t *Fount) Stop() {
	t.Timer.Stop()
}

// NewTimer is used to create a new Fount. A subsequent
// call to the Start method is used to activate the timer.
func NewTimer(desc *Descriptor) *Fount {
	t := &Fount{
		rng:  rand.NewMath(),
		desc: desc,
	}
	return t
}
