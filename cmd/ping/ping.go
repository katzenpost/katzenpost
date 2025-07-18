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
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/charmbracelet/lipgloss/v2"
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/thin"
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

// Color styles for ping output
var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true) // Bright green
	failureStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)  // Bright red
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true) // Bright cyan
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true) // Bright yellow
)

func sendPing(session *thin.ThinClient, serviceDesc *common.ServiceDescriptor, printDiff bool) bool {
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

	id := hash.Sum256(serviceDesc.MixDescriptor.IdentityKey)

	ctx := context.TODO()
	reply, err := session.BlockingSendMessage(ctx, cborPayload, &id, serviceDesc.RecipientQueueID)
	if err != nil {
		fmt.Printf("\nerror: %v\n", err)
		fmt.Printf("%s", failureStyle.Render(".")) // Fail, did not receive a reply.
		return false
	}

	var replyPayload []byte

	_, err = cbor.UnmarshalFirst(reply, &replyPayload)
	if err != nil {
		fmt.Printf("Failed to unmarshal: %s\n", err)
		panic(err)
	}

	if bytes.Equal(replyPayload, pingPayload) {
		// OK, received identical payload in reply.hash.Sum256(serviceDesc.MixDescriptor.IdentityKey)
		return true
	} else {
		// Fail, received unexpected payload in reply.

		if printDiff {
			fmt.Printf("\nReply payload: %x\nOriginal payload: %x\n", replyPayload, pingPayload)
		}
		return false
	}
}

func sendPings(session *thin.ThinClient, serviceDesc *common.ServiceDescriptor, count int, concurrency int, printDiff bool) {
	// Extract service name from RecipientQueueID (remove leading '+' if present)
	serviceName := string(serviceDesc.RecipientQueueID)
	nodeName := serviceDesc.MixDescriptor.Name

	fmt.Println("Control-C to abort...")
	fmt.Printf("%s\n", headerStyle.Render(fmt.Sprintf("Sending %d Sphinx packets to %s@%s", count, serviceName, nodeName)))

	var passed, failed uint64

	wg := new(sync.WaitGroup)
	sem := make(chan struct{}, concurrency)

	for i := 0; i < count; i++ {

		sem <- struct{}{}

		wg.Add(1)

		// make new goroutine for each ping to send them in parallel
		go func() {
			if sendPing(session, serviceDesc, printDiff) {
				fmt.Printf("%s", successStyle.Render("!"))
				atomic.AddUint64(&passed, 1)
			} else {
				fmt.Printf("%s", failureStyle.Render("~"))
				atomic.AddUint64(&failed, 1)
			}
			wg.Done()
			<-sem
		}()
	}

	wg.Wait()
	fmt.Printf("\n")

	percent := (float64(passed) * float64(100)) / float64(count)
	successMsg := fmt.Sprintf("Success rate is %.0f percent (%d/%d)", percent, passed, count)
	if percent >= 90.0 {
		fmt.Printf("%s\n", successStyle.Render(successMsg))
	} else if percent >= 50.0 {
		fmt.Printf("%s\n", infoStyle.Render(successMsg))
	} else {
		fmt.Printf("%s\n", failureStyle.Render(successMsg))
	}
}
