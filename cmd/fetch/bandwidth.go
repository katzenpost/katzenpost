// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func printBandwidth(client *thin.ThinClient) error {
	raw, _, err := client.GetPKIDocumentRaw(0)
	if err != nil {
		return fmt.Errorf("no consensus document to estimate from: %v", err)
	}
	doc, err := cpki.ParseDocument(raw)
	if err != nil {
		return err
	}
	b := thin.EstimateBandwidth(doc.LambdaP, doc.LambdaL, true, client.GetSphinxGeometry(), len(raw), epochtime.Period())
	fmt.Printf("Estimated bandwidth for epoch %d with decoy traffic: %s\n", doc.Epoch, b)
	return nil
}
