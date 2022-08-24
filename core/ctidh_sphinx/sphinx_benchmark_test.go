// sphinx_benchmark_test.go - Sphinx Packet Format benchmarks.
// Copyright (C) 2018 Yawning Angel, David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package ctidh_sphinx

import (
	"crypto/rand"
	"testing"

	ctidh "git.xx.network/elixxir/ctidh_cgo"

	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func benchNewNode() *nodeParams {
	n := new(nodeParams)
	_, err := rand.Read(n.id[:])
	if err != nil {
		panic("wtf")
	}
	n.privateKey, _, err = ctidh.GenerateKeyPair()
	if err != nil {
		panic("wtf")
	}
	return n
}

func benchNewPathVector(nrHops int, isSURB bool) ([]*nodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*nodeParams, nrHops)
	for i := range nodes {
		nodes[i] = benchNewNode()
	}

	// Assemble the path vector.
	path := make([]*PathHop, nrHops)
	for i := range path {
		path[i] = new(PathHop)
		copy(path[i].ID[:], nodes[i].id[:])

		var err error
		path[i].PublicKey, err = ctidh.DerivePublicKey(nodes[i].privateKey)
		if err != nil {
			panic(err)
		}
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Read(recipient.ID[:])
			if err != nil {
				panic("wtf")
			}
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Read(surbReply.ID[:])
				if err != nil {
					panic("wtf")
				}
				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path
}

func BenchmarkSphinxUnwrap(b *testing.B) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."
	nodes, path := benchNewPathVector(constants.NrHops, false)
	payload := []byte(testPayload)
	pkt, err := NewPacket(rand.Reader, path, payload)
	if err != nil {
		panic("wtf")
	}
	if len(pkt) != HeaderLength+PayloadTagLength+len(payload) {
		panic("wtf")
	}

	for n := 0; n < b.N; n++ {
		testPacket := make([]byte, len(pkt))
		copy(testPacket, pkt)
		_, _, _, err := Unwrap(nodes[0].privateKey, testPacket)
		if err != nil {
			panic("wtf")
		}
	}
}
