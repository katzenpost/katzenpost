// ping.go - Katzenpost ping tool
// Copyright (C) 2021  David Stainton
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

package main

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

var basePayload = []byte(`Data encryption is used widely to protect the content of Internet
communications and enables the myriad of activities that are popular today,
from online banking to chatting with loved ones. However, encryption is not
sufficient to protect the meta-data associated with the communications.

Modern encrypted communication networks are vulnerable to traffic analysis and
can leak such meta-data as the social graph of users, their geographical
location, the timing of messages and their order, message size, and many other
kinds of meta-data.

Since 1979, there has been active academic research into communication
meta-data protection, also called anonymous communication networking, that has
produced various designs. Of these, mix networks are among the most practical
and can readily scale to millions of users.
`)

func sequentialPing(session *client.Session, serviceDesc *utils.ServiceDescriptor, count int, printDiff bool) {
	fmt.Printf("Sending %d Sphinx packet payloads to: %s@%s\n", count, serviceDesc.Name, serviceDesc.Provider)

	passed := 0
	failed := 0
	for i := 0; i < count; i++ {

		var nonce [32]byte

		_, err := rand.Reader.Read(nonce[:])

		if err != nil {
			panic(err)
		}

		pingPayload := append(nonce[:], basePayload...)

		cborPayload, err := cbor.Marshal(pingPayload)
		if err != nil {
			fmt.Printf("Failed to marshal: %v\n", err)
			panic(err)
		}

		reply, err := session.BlockingSendUnreliableMessage(serviceDesc.Name, serviceDesc.Provider, cborPayload)
		if err != nil {
			failed++
			fmt.Printf(".") // Fail, did not receive a reply.
			continue
		}

		var replyPayload []byte

		err = cbor.Unmarshal(reply, &replyPayload)
		if err != nil {
			fmt.Printf("Failed to unmarshal: %s\n", err)
			panic(err)
		}

		if bytes.Equal(replyPayload, pingPayload) {
			passed++
			fmt.Printf("!") // OK, received identical payload in reply.
		} else {
			fmt.Printf("~") // Fail, received unexpected payload in reply.

			if printDiff {
				fmt.Printf("\nReply payload: %x\nOriginal payload: %x\n", replyPayload, pingPayload)
			}
		}
	}
	fmt.Printf("\n")

	percent := (float64(passed) * float64(100)) / float64(count)
	fmt.Printf("Success rate is %f percent %d/%d)\n", percent, passed, count)
}
