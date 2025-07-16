// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import cpki "github.com/katzenpost/katzenpost/core/pki"

type Rates struct {
	messageOrLoop         float64
	messageOrLoopMaxDelay uint64
}

func ratesFromPKIDoc(doc *cpki.Document) *Rates {
	return &Rates{
		messageOrLoop:         doc.LambdaP,
		messageOrLoopMaxDelay: doc.LambdaPMaxDelay,
	}
}
