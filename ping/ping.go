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
	"sync"
	"sync/atomic"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/hpqc/rand"
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

func sendPing(session *client.Session, serviceDesc *utils.ServiceDescriptor, printDiff bool) bool {
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
		fmt.Printf("\nerror: %v\n", err)
		fmt.Printf(".") // Fail, did not receive a reply.
		return false
	}

	var replyPayload []byte

	_, err = cbor.UnmarshalFirst(reply, &replyPayload)
	if err != nil {
		fmt.Printf("Failed to unmarshal: %s\n", err)
		panic(err)
	}

	if bytes.Equal(replyPayload, pingPayload) {
		// OK, received identical payload in reply.
		return true
	} else {
		// Fail, received unexpected payload in reply.

		if printDiff {
			fmt.Printf("\nReply payload: %x\nOriginal payload: %x\n", replyPayload, pingPayload)
		}
		return false
	}
}

func sendPings(session *client.Session, serviceDesc *utils.ServiceDescriptor, count int, concurrency int, printDiff bool) {
	if concurrency > constants.MaxEgressQueueSize {
		fmt.Printf("error: concurrency cannot be greater than MaxEgressQueueSize (%d)\n", constants.MaxEgressQueueSize)
		return
	}
	fmt.Printf("Sending %d Sphinx packets to %s@%s\n", count, serviceDesc.Name, serviceDesc.Provider)

	var passed, failed uint64

	wg := new(sync.WaitGroup)
	sem := make(chan struct{}, concurrency)

	for i := 0; i < count; i++ {

		sem <- struct{}{}

		wg.Add(1)

		// make new goroutine for each ping to send them in parallel
		go func() {
			if sendPing(session, serviceDesc, printDiff) {
				fmt.Printf("!")
				atomic.AddUint64(&passed, 1)
			} else {
				fmt.Printf("~")
				atomic.AddUint64(&failed, 1)
			}
			wg.Done()
			<-sem
		}()
	}
	fmt.Printf("\n")

	wg.Wait()

	percent := (float64(passed) * float64(100)) / float64(count)
	fmt.Printf("Success rate is %f percent %d/%d)\n", percent, passed, count)
}
