// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

type docView struct {
	Epoch              uint64
	GenesisEpoch       uint64
	SharedRandomValue  string
	SphinxGeometryHash string
	Version            string
	PKISignatureScheme string
	Mu                 float64
	LambdaP            float64
	LambdaL            float64
	LambdaM            float64
	LambdaG            float64
	LambdaR            float64
	Layers             [][]string
	Gateways           []string
	ServiceNodes       []string
	StorageReplicas    []string
	Signers            []string
}

func mixNames(descs []*cpki.MixDescriptor) []string {
	names := make([]string, len(descs))
	for i, d := range descs {
		names[i] = d.Name
	}
	return names
}

func newDocView(doc *cpki.Document, signerNames map[[32]byte]string) docView {
	v := docView{
		Epoch:              doc.Epoch,
		GenesisEpoch:       doc.GenesisEpoch,
		SharedRandomValue:  hex.EncodeToString(doc.SharedRandomValue),
		SphinxGeometryHash: hex.EncodeToString(doc.SphinxGeometryHash),
		Version:            doc.Version,
		PKISignatureScheme: doc.PKISignatureScheme,
		Mu:                 doc.Mu,
		LambdaP:            doc.LambdaP,
		LambdaL:            doc.LambdaL,
		LambdaM:            doc.LambdaM,
		LambdaG:            doc.LambdaG,
		LambdaR:            doc.LambdaR,
		Layers:             make([][]string, len(doc.Topology)),
		Gateways:           mixNames(doc.GatewayNodes),
		ServiceNodes:       mixNames(doc.ServiceNodes),
		StorageReplicas:    make([]string, len(doc.StorageReplicas)),
		Signers:            make([]string, 0, len(doc.Signatures)),
	}
	for i, layer := range doc.Topology {
		v.Layers[i] = mixNames(layer)
	}
	for i, r := range doc.StorageReplicas {
		v.StorageReplicas[i] = r.Name
	}
	for fp := range doc.Signatures {
		if name := signerNames[fp]; name != "" {
			v.Signers = append(v.Signers, name)
		} else {
			v.Signers = append(v.Signers, hex.EncodeToString(fp[:]))
		}
	}
	sort.Strings(v.Signers)
	return v
}

func (v docView) text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "epoch %d (genesis %d)\n", v.Epoch, v.GenesisEpoch)
	fmt.Fprintf(&b, "srv %s\n", v.SharedRandomValue)
	fmt.Fprintf(&b, "version %s scheme %s geometry %s\n", v.Version, v.PKISignatureScheme, v.SphinxGeometryHash)
	fmt.Fprintf(&b, "mu %g lambdaP %g lambdaL %g lambdaM %g lambdaG %g lambdaR %g\n", v.Mu, v.LambdaP, v.LambdaL, v.LambdaM, v.LambdaG, v.LambdaR)
	for i, layer := range v.Layers {
		fmt.Fprintf(&b, "layer %d: %s\n", i, strings.Join(layer, " "))
	}
	fmt.Fprintf(&b, "gateways: %s\n", strings.Join(v.Gateways, " "))
	fmt.Fprintf(&b, "service nodes: %s\n", strings.Join(v.ServiceNodes, " "))
	fmt.Fprintf(&b, "replicas: %s\n", strings.Join(v.StorageReplicas, " "))
	fmt.Fprintf(&b, "signers: %s\n", strings.Join(v.Signers, " "))
	return b.String()
}

func formatDocument(doc *cpki.Document, format string, signerNames map[[32]byte]string) (string, error) {
	v := newDocView(doc, signerNames)
	switch format {
	case "text":
		return v.text(), nil
	case "json":
		out, err := json.MarshalIndent(v, "", "  ")
		return string(out) + "\n", err
	}
	return "", fmt.Errorf("unknown format %q, want text or json", format)
}
