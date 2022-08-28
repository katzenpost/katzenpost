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

package sphinx

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/nike"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

/*


 */

func benchmarkSphinxUnwrap(b *testing.B, mynike nike.Nike) {
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."
	sphinx := NewSphinx(mynike, len(testPayload), 5)

	nodes, path := benchNewPathVector(sphinx.nrHops, false, mynike)
	payload := []byte(testPayload)

	pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
	if err != nil {
		panic("wtf")
	}
	if len(pkt) != sphinx.HeaderLength()+PayloadTagLength+len(payload) {
		panic("wtf")
	}

	for n := 0; n < b.N; n++ {
		testPacket := make([]byte, len(pkt))
		copy(testPacket, pkt)
		_, _, _, err := sphinx.Unwrap(nodes[0].privateKey, testPacket)
		if err != nil {
			panic("wtf")
		}
	}
}

func benchNewNode(mynike nike.Nike) *nodeParams {
	n := new(nodeParams)
	_, err := rand.Read(n.id[:])
	if err != nil {
		panic("wtf")
	}
	n.privateKey, n.publicKey = mynike.NewKeypair()
	return n
}

func benchNewPathVector(nrHops int, isSURB bool, mynike nike.Nike) ([]*nodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*nodeParams, nrHops)
	for i := range nodes {
		nodes[i] = benchNewNode(mynike)
	}

	// Assemble the path vector.
	path := make([]*PathHop, nrHops)
	for i := range path {
		path[i] = new(PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].PublicKey = nodes[i].publicKey
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
