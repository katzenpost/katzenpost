// main.go - Generates KEM-Sphinx full-packet test vectors, for the Lean port
// in CryptWalker (https://github.com/katzenpost/CryptWalker).
//
// Structurally parallel to sphinx_vectors_test.go's
// NoTestBuildFileVectorSphinx/buildVectorSphinx (the NIKE-Sphinx vector
// generator), but built entirely on core/sphinx's exported API rather than
// from inside package sphinx, since there is no existing KEM-Sphinx vector
// file or in-package generator to extend.
//
// The KEM is X25519 via hpqc's NIKE-to-KEM adapter using the portable
// sha256-v1 PRF (adapter.SHA256v1), not the deployed BLAKE2b-XOF one --
// matching CryptWalker's KEM/Adapter.lean, which only has sha256-v1 ported.
//
// Run from the repository root:
//
//	go run ./core/sphinx/testvectors/cmd/generate_kem
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type hexNodeParams struct {
	ID         string
	PrivateKey string
}

type hexPathHop struct {
	ID        string
	PublicKey string
	Commands  []string
}

type hexSphinxTest struct {
	Nodes    []hexNodeParams
	Path     []hexPathHop
	Packets  []string
	Payload  string
	Surb     string
	SurbKeys string
}

// Same string sphinx_vectors_test.go uses (103 UTF-8 bytes, matching the
// geometry's UserForwardPayloadLength below), for easy diffing against the
// NIKE vectors.
const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

type nodeParams struct {
	id         [32]byte
	privateKey kem.PrivateKey
	publicKey  kem.PublicKey
}

func newKemNode(k kem.Scheme) *nodeParams {
	n := new(nodeParams)
	if _, err := rand.Read(n.id[:]); err != nil {
		panic(err)
	}
	pk, sk, err := k.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	n.publicKey, n.privateKey = pk, sk
	return n
}

func newKemPathVector(k kem.Scheme, nrHops int, isSURB bool) ([]*nodeParams, []*sphinx.PathHop) {
	const delayBase = 0xdeadbabe
	nodes := make([]*nodeParams, nrHops)
	for i := range nodes {
		nodes[i] = newKemNode(k)
	}
	path := make([]*sphinx.PathHop, nrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].KEMPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			recipient := new(commands.Recipient)
			if _, err := rand.Read(recipient.ID[:]); err != nil {
				panic(err)
			}
			path[i].Commands = append(path[i].Commands, recipient)
			if isSURB {
				surbReply := new(commands.SURBReply)
				if _, err := rand.Read(surbReply.ID[:]); err != nil {
					panic(err)
				}
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}
	return nodes, path
}

func buildVectorKEMSphinx(k kem.Scheme, withSURB bool, s *sphinx.Sphinx) []hexSphinxTest {
	tests := make([]hexSphinxTest, s.Geometry().NrHops+1)
	for nrHops := 1; nrHops <= s.Geometry().NrHops; nrHops++ {
		nodes, path := newKemPathVector(k, nrHops, withSURB)

		hexNodes := make([]hexNodeParams, len(nodes))
		for i, node := range nodes {
			skBytes, err := node.privateKey.MarshalBinary()
			if err != nil {
				panic(err)
			}
			hexNodes[i] = hexNodeParams{
				ID:         hex.EncodeToString(node.id[:]),
				PrivateKey: hex.EncodeToString(skBytes),
			}
		}

		hexPath := make([]hexPathHop, len(path))
		for i, hop := range path {
			pkBytes, err := hop.KEMPublicKey.MarshalBinary()
			if err != nil {
				panic(err)
			}
			hexPath[i] = hexPathHop{
				ID:        hex.EncodeToString(hop.ID[:]),
				PublicKey: hex.EncodeToString(pkBytes),
				Commands:  make([]string, len(hop.Commands)),
			}
			for j, cmd := range hop.Commands {
				hexPath[i].Commands[j] = hex.EncodeToString(cmd.ToBytes([]byte{}))
			}
		}

		var pkt []byte
		surb := []byte{}
		surbKeys := []byte{}
		payload := []byte(testPayload)
		var err error
		if withSURB {
			surb, surbKeys, err = s.NewSURB(rand.Reader, path)
			if err != nil {
				panic(err)
			}
			pkt, _, err = s.NewPacketFromSURB(surb, payload)
			if err != nil {
				panic(err)
			}
		} else {
			pkt, err = s.NewPacket(rand.Reader, path, payload)
			if err != nil {
				panic(err)
			}
		}

		tests[nrHops] = hexSphinxTest{
			Nodes:    hexNodes,
			Path:     hexPath,
			Packets:  make([]string, len(nodes)+1),
			Surb:     hex.EncodeToString(surb),
			SurbKeys: hex.EncodeToString(surbKeys),
		}
		tests[nrHops].Packets[0] = hex.EncodeToString(pkt)

		for i := range nodes {
			b, _, _, err := s.Unwrap(nodes[i].privateKey, pkt)
			if err != nil {
				panic(fmt.Sprintf("nrHops=%d hop=%d: %s", nrHops, i, err))
			}
			if i == len(path)-1 {
				if withSURB {
					b, err = s.DecryptSURBPayload(b, surbKeys)
					if err != nil {
						panic(err)
					}
				}
				tests[nrHops].Payload = hex.EncodeToString(b)
			} else {
				tests[nrHops].Packets[i+1] = hex.EncodeToString(pkt)
			}
		}
	}
	return tests[1:]
}

func main() {
	k := adapter.FromNIKEWithPRF(x25519.Scheme(rand.Reader), adapter.SHA256v1)

	withSURB := false
	g := geo.KEMGeometryFromUserForwardPayloadLength(k, 103, withSURB, 5)
	s := sphinx.NewKEMSphinx(k, g)
	hexTests := buildVectorKEMSphinx(k, withSURB, s)

	withSURB = true
	g = geo.KEMGeometryFromUserForwardPayloadLength(k, 103, withSURB, 5)
	s = sphinx.NewKEMSphinx(k, g)
	hexTests2 := buildVectorKEMSphinx(k, withSURB, s)

	hexTests = append(hexTests, hexTests2...)

	serialized, err := json.Marshal(hexTests)
	if err != nil {
		panic(err)
	}

	const outPath = "core/sphinx/testdata/kemsphinx_vectors.json"
	if err := os.WriteFile(outPath, serialized, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", outPath)
}
