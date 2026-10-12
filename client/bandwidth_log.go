// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func (d *Daemon) logBandwidth(doc *cpki.Document, docLen int) {
	rates := [2]float64{doc.LambdaP, doc.LambdaL}
	if d.loggedRatesSet && rates == d.loggedRates {
		return
	}
	d.loggedRatesSet = true
	d.loggedRates = rates
	b := thin.EstimateBandwidth(doc.LambdaP, doc.LambdaL, !d.cfg.Debug.DisableDecoyTraffic, d.cfg.SphinxGeometry, docLen, epochtime.Period())
	d.log.Infof("Estimated bandwidth: %s", b)
}
