// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-or-later

package sphinx

import (
	"crypto/rand"
	"testing"

	kemScheme "github.com/katzenpost/hpqc/kem/schemes"
	nikeScheme "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

var benchmarks = []struct {
	name        string
	isNIKE      bool // KEM if false
	nikeName    string
	kemName     string
	nrHops      int
	payloadSize int
}{
	// NIKEs
	{
		name:        "X25519 NIKE",
		isNIKE:      true,
		nikeName:    "x25519",
		kemName:     "",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "X448 NIKE",
		isNIKE:      true,
		nikeName:    "x448",
		kemName:     "",
		nrHops:      5,
		payloadSize: 2000,
	},

	{
		name:        "CTIDH512 PQ NIKE",
		isNIKE:      true,
		nikeName:    "CTIDH512",
		kemName:     "",
		nrHops:      5,
		payloadSize: 2000,
	},
	// There's some kind of bug preventing this one from working.
	/*
		{
			name:        "CTIDH512-X25519 PQ Hybrid NIKE",
			isNIKE:      true,
			nikeName:    "CTIDH512-X25519",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},
	*/
	{
		name:        "CTIDH512-X448 PQ Hybrid NIKE",
		isNIKE:      true,
		nikeName:    "CTIDH512-X448",
		kemName:     "",
		nrHops:      5,
		payloadSize: 2000,
	},

	{
		name:        "CTIDH1024 PQ NIKE",
		isNIKE:      true,
		nikeName:    "CTIDH1024",
		kemName:     "",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "CTIDH1024-X448 PQ Hybrid NIKE",
		isNIKE:      true,
		nikeName:    "CTIDH1024-X448",
		kemName:     "",
		nrHops:      5,
		payloadSize: 2000,
	},

	// NIKEs adapted as KEMs (via adhoc hashed elgamal construction)
	{
		name:        "X25519 KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "x25519",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "X448 KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "x448",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "CTIDH512 PQ KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "CTIDH512",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "CTIDH1024 PQ KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "CTIDH1024",
		nrHops:      5,
		payloadSize: 2000,
	},

	// PQ KEMs
	{
		name:        "MLKEM768 KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "MLKEM768",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "sntrup4591761 KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "sntrup4591761",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "FrodoKEM-640-SHAKE KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "FrodoKEM-640-SHAKE",
		nrHops:      5,
		payloadSize: 2000,
	},

	// hybrid KEMs
	{
		name:        "Xwing KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "Xwing",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "MLKEM768-X25519 KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "MLKEM768-X25519",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "MLKEM768-X448 KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "MLKEM768-X448",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "CTIDH512-X25519 PQ Hybrid KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "CTIDH512-X25519",
		nrHops:      5,
		payloadSize: 2000,
	},
	{
		name:        "CTIDH1024-X448 PQ Hybrid KEM",
		isNIKE:      false,
		nikeName:    "",
		kemName:     "CTIDH1024-X448",
		nrHops:      5,
		payloadSize: 2000,
	},
}

func BenchmarkSphinxCreatePackets(b *testing.B) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	for _, bm := range benchmarks {
		b.Logf("test case: %s", bm.name)
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if bm.isNIKE {
					scheme := nikeScheme.ByName(bm.nikeName)
					if scheme == nil {
						panic("NIKE scheme is nil")
					}
					g := geo.GeometryFromUserForwardPayloadLength(scheme, bm.payloadSize, false, bm.nrHops)
					sphinx := NewSphinx(g)

					_, path := benchNewPathVector(g.NrHops, false, scheme)
					payload := make([]byte, bm.payloadSize)
					copy(payload[:len(testPayload)], testPayload) // some kind of payload that is not all zero bytes

					b.StartTimer()
					_, err := sphinx.NewPacket(rand.Reader, path, payload)
					if err != nil {
						panic(err)
					}
				} else { // KEM
					b.StopTimer()
					scheme := kemScheme.ByName(bm.kemName)
					if scheme == nil {
						panic("NIKE scheme is nil")
					}
					g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, bm.payloadSize, false, bm.nrHops)
					sphinx := NewSphinx(g)

					_, path := newBenchKEMPathVector(scheme, g.NrHops, false)
					payload := make([]byte, bm.payloadSize)
					copy(payload[:len(testPayload)], testPayload) // some kind of payload that is not all zero bytes

					b.StartTimer()
					_, err := sphinx.NewPacket(rand.Reader, path, payload)
					if err != nil {
						panic(err)
					}
				}
			}
		})
	}
}

func BenchmarkSphinxUnwrap(b *testing.B) {

	for _, bm := range benchmarks {
		b.Logf("test case: %s", bm.name)
		prep := prepareSphinxBenchmark(bm.isNIKE, bm.nikeName, bm.kemName, bm.nrHops, bm.payloadSize)

		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {

				b.StopTimer()
				testPacket := make([]byte, len(prep.packet))
				copy(testPacket, prep.packet)
				b.StartTimer()

				_, _, _, err := prep.sphinx.Unwrap(prep.privateKey, testPacket)
				if err != nil {
					panic(err)
				}
			}
		})
	}
}

type preparedBenchTest struct {
	sphinx     *Sphinx
	packet     []byte
	privateKey interface{}
}

func prepareSphinxBenchmark(isNIKE bool, nikeName string, kemName string, nrHops int, payloadSize int) *preparedBenchTest {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	if isNIKE {
		scheme := nikeScheme.ByName(nikeName)
		if scheme == nil {
			panic("NIKE scheme is nil")
		}
		g := geo.GeometryFromUserForwardPayloadLength(scheme, payloadSize, false, nrHops)
		sphinx := NewSphinx(g)

		nodes, path := benchNewPathVector(g.NrHops, false, scheme)
		payload := make([]byte, payloadSize)
		copy(payload[:len(testPayload)], testPayload) // some kind of payload that is not all zero bytes

		pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
		if err != nil {
			panic(err)
		}

		return &preparedBenchTest{
			sphinx:     sphinx,
			packet:     pkt,
			privateKey: nodes[0].privateKey,
		}
	} else { // KEM
		scheme := kemScheme.ByName(kemName)
		if scheme == nil {
			panic("NIKE scheme is nil")
		}
		g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, payloadSize, false, nrHops)
		sphinx := NewSphinx(g)

		nodes, path := newBenchKEMPathVector(scheme, g.NrHops, false)
		payload := make([]byte, payloadSize)
		copy(payload[:len(testPayload)], testPayload) // some kind of payload that is not all zero bytes

		pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
		if err != nil {
			panic(err)
		}

		return &preparedBenchTest{
			sphinx:     sphinx,
			packet:     pkt,
			privateKey: nodes[0].privateKey,
		}
	}

	panic("invalid state")

	return nil
}
