// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import cpki "github.com/katzenpost/katzenpost/core/pki"

type Rates struct {
	messageOrDrop         float64
	messageOrDropMaxDelay uint64

	loop         float64
	loopMaxDelay uint64

	drop         float64
	dropMaxDelay uint64
}

func ratesFromPKIDoc(doc *cpki.Document) *Rates {
	return &Rates{
		messageOrDrop:         doc.LambdaP,
		messageOrDropMaxDelay: doc.LambdaPMaxDelay,
		loop:                  doc.LambdaL,
		loopMaxDelay:          doc.LambdaLMaxDelay,
		drop:                  doc.LambdaD,
		dropMaxDelay:          doc.LambdaDMaxDelay,
	}
}
