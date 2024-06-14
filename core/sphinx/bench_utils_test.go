// SPDX-FileCopyrightText: Copyright (C) 2018-2024 Yawning Angel, David Stainton.
// SPDX-License-Identifier: AGPL-3.0-or-later

package sphinx

import (
	"crypto/rand"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
)

func benchNewNode(mynike nike.Scheme) *nodeParams {
	n := new(nodeParams)
	_, err := rand.Read(n.id[:])
	if err != nil {
		panic(err)
	}
	n.publicKey, n.privateKey, err = mynike.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	return n
}

func benchNewPathVector(nrHops int, isSURB bool, mynike nike.Scheme) ([]*nodeParams, []*PathHop) {
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
		path[i].NIKEPublicKey = nodes[i].publicKey
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

func benchNewKEMNode(mykem kem.Scheme) *kemNodeParams {
	n := new(kemNodeParams)

	_, err := rand.Reader.Read(n.id[:])
	if err != nil {
		panic("wtf")
	}
	n.publicKey, n.privateKey, err = mykem.GenerateKeyPair()
	if err != nil {
		panic("wtf")
	}
	return n
}

func newBenchKEMPathVector(mykem kem.Scheme, nrHops int, isSURB bool) ([]*kemNodeParams, []*PathHop) {
	const delayBase = 0xdeadbabe

	// Generate the keypairs and node identifiers for the "nodes".
	nodes := make([]*kemNodeParams, nrHops)
	for i := range nodes {
		nodes[i] = benchNewKEMNode(mykem)
	}

	// Assemble the path vector.
	path := make([]*PathHop, nrHops)
	for i := range path {
		path[i] = new(PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].KEMPublicKey = nodes[i].publicKey
		if i < nrHops-1 {
			// Non-terminal hop, add the delay.
			delay := new(commands.NodeDelay)
			delay.Delay = delayBase * uint32(i+1)
			path[i].Commands = append(path[i].Commands, delay)
		} else {
			// Terminal hop, add the recipient.
			recipient := new(commands.Recipient)
			_, err := rand.Reader.Read(recipient.ID[:])
			if err != nil {
				panic(err)
			}
			path[i].Commands = append(path[i].Commands, recipient)

			// This is a SURB, add a surb_reply.
			if isSURB {
				surbReply := new(commands.SURBReply)
				_, err := rand.Reader.Read(surbReply.ID[:])
				if err != nil {
					panic(err)
				}

				path[i].Commands = append(path[i].Commands, surbReply)
			}
		}
	}

	return nodes, path
}
