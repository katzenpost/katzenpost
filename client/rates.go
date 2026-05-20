// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import cpki "github.com/katzenpost/katzenpost/core/pki"

// Rates carries the two cover-traffic rates that the client's sender
// consumes:
//
//   - messageOrLoop / messageOrLoopMaxDelay are LambdaP and
//     LambdaPMaxDelay from the consensus document. The sender emits a
//     real request from the FIFO on each LambdaP tick, falling back
//     to a loop decoy when the FIFO is empty.
//
//   - loop / loopMaxDelay are LambdaL and LambdaLMaxDelay. The sender
//     emits a loop decoy on each LambdaL tick independent of the FIFO
//     state, providing the Loopix "loop traffic" cover stream.
type Rates struct {
	messageOrLoop         float64
	messageOrLoopMaxDelay uint64

	loop         float64
	loopMaxDelay uint64
}

func ratesFromPKIDoc(doc *cpki.Document) *Rates {
	return &Rates{
		messageOrLoop:         doc.LambdaP,
		messageOrLoopMaxDelay: doc.LambdaPMaxDelay,
		loop:                  doc.LambdaL,
		loopMaxDelay:          doc.LambdaLMaxDelay,
	}
}
