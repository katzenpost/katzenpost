// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"github.com/katzenpost/katzenpost/core/worker"
)

func (s *Server) startRegistrationHandler() {

}

type Reg struct {
	worker.Worker
}

func (r *Reg) start() {
	r.Go(r.worker)
}

func (r *Reg) worker() {
	for {
		select {
		case <-r.HaltCh():
			return
		case wtf:

		}
	}
}
