// periodic.go - Katzenpost server periodic timer.
// Copyright (C) 2017  Yawning Angel.
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

package server

import (
	"sync"
	"time"
)

type periodicTimer struct {
	sync.WaitGroup

	s *Server

	haltCh chan interface{}
}

func (t *periodicTimer) halt() {
	close(t.haltCh)
	t.Wait()
}

func (t *periodicTimer) worker() {
	ticker := time.NewTicker(time.Second)
	defer func() {
		ticker.Stop()
		t.Done()
	}()

	lastCallbackTime := time.Now()

	for {
		select {
		case <-t.haltCh:
			return
		case <-ticker.C:
		}

		// Do periodic housekeeping tasks at a rate of approximately 1 Hz.
		//
		// Most of these calls can be scheduled much more infrequently, but
		// the no-op case is cheap enough that it probably doesn't matter.
		//
		// WARNING: None of the operations done here should block.  If there's
		// a need to do anything that's long lived, then it MUST be done async
		// in a go routine.

		// Ensure civil time sanity.
		//
		// TODO: Not sure what to do when the clock jumps around, it probably
		// screws with epoch timing and PKI interactions, but everything
		// should keep working, for varying amounts of "working".
		now := time.Now()
		deltaT := now.Sub(lastCallbackTime)
		if deltaT < 0 {
			t.s.log.Warning("Civil time jumped backwards: %v", deltaT)
		} else if deltaT > 2*time.Second {
			t.s.log.Warning("Civil time jumped forward: %v", deltaT)
		}

		// TODO: Figure out what needs to be triggered from the top level
		// server instead of from timers belonging to a sub component.

		// Stash the time we got unblocked as the last callback time.
		lastCallbackTime = now
	}
}

func newPeriodicTimer(s *Server) *periodicTimer {
	t := new(periodicTimer)
	t.s = s
	t.haltCh = make(chan interface{})
	t.Add(1)

	go t.worker()
	return t
}
