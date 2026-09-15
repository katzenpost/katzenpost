// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import cpki "github.com/katzenpost/katzenpost/core/pki"

// Rates carries the two cover-traffic rates that the client's sender
// consumes:
//
//   - messageOrLoop is LambdaP from the consensus document. The sender
//     emits a real request from the FIFO on each LambdaP tick, falling
//     back to a loop decoy when the FIFO is empty.
//
//   - loop is LambdaL. The sender emits a loop decoy on each LambdaL
//     tick independent of the FIFO state, providing the Loopix "loop
//     traffic" cover stream.
//
// Sampling safety caps are derived inside the ExpDist worker from the
// rate value, so no MaxDelay companion is required here.
type Rates struct {
	messageOrLoop float64
	loop          float64
}

func ratesFromPKIDoc(doc *cpki.Document) *Rates {
	return &Rates{
		messageOrLoop: doc.LambdaP,
		loop:          doc.LambdaL,
	}
}
