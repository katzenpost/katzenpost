// worker.go - Background worker tasks.
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

// Package worker provides background worker tasks.
package worker

import "sync"

// Worker is a set of managed background go routines.
type Worker struct {
	sync.WaitGroup
	initOnce sync.Once

	haltCh chan interface{}
}

// Go excutes the function fn in a new Go routine.  Multiple Go routines may
// be started under the same Worker.  It is the function's responsiblity to
// monitor the channel returned by `Worker.HaltCh()` and to return.
func (w *Worker) Go(fn func()) {
	w.initOnce.Do(w.init)
	w.Add(1)
	go func() {
		defer w.Done()
		fn()
	}()
}

// Halt signals all Go routines started under a Worker to terminate, and waits
// till all go routines have returned.
func (w *Worker) Halt() {
	w.initOnce.Do(w.init)
	close(w.haltCh)
	w.Wait()
}

// HaltCh returns the channel that will be closed on a call to Halt.
func (w *Worker) HaltCh() <-chan interface{} {
	w.initOnce.Do(w.init)
	return w.haltCh
}

func (w *Worker) init() {
	w.haltCh = make(chan interface{})
}
