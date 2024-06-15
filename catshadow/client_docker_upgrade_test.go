// SPDX-FileCopyrightText: 2024 Katzenpost developers
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// client.go - client
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

//go:build docker_test
// +build docker_test

package catshadow

import (
	"context"
	"testing"
	"time"
	"os"

	_ "net/http/pprof"

	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
)


func TestXXXUpgradeCreate(t *testing.T) {
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceStateFilePath)
	bobStateFilePath := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobStateFilePath)

	sharedSecret := []byte(`oxcart pillage village bicycle gravity socks`)
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	bobKXFinishedChan := make(chan bool)
	bobReceivedMessageChan := make(chan bool)
	bobSentChan := make(chan bool)
	bobDeliveredChan := make(chan bool)

	go func() {
		sentEventSeenIds := make(map[MessageID]bool)
		for {
			ev, ok := <-bob.EventSink
			if !ok {
				return
			}
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				bob.log.Debugf("CSTDSR: BOB GOT KEYEX COMPLETED")
				require.Nil(event.Err)
				bobKXFinishedChan <- true
			case *MessageReceivedEvent:
				// fields: Nickname, Message, Timestamp
				bob.log.Debugf("CSTDSR: BOB RECEIVED MESSAGE from %s:\n%s", event.Nickname, string(event.Message))
				bobReceivedMessageChan <- true
			case *MessageDeliveredEvent:
				bob.log.Debugf("CSTDSR: BOB GOT DELIVERED EVENT")
				require.Equal(event.Nickname, "mal")
				bobDeliveredChan <- true
			case *MessageSentEvent:
				if _, ok = sentEventSeenIds[event.MessageID]; ok {
					bob.log.Debugf("CSTDSR: BOB GOT DUPE SENT MESSAGE %x to %s", event.MessageID, event.Nickname)
					continue
				}
				sentEventSeenIds[event.MessageID] = true
				bob.log.Debugf("CSTDSR: BOB SENT MESSAGE %x to %s", event.MessageID, event.Nickname)
				require.Equal(event.Nickname, "mal")
				bobSentChan <- true
			default:
				bob.log.Debugf("CSTDSR: BOB EVENTSINK GOT EVENT %t", ev)
			}
		}
	}()

	aliceKXFinishedChan := make(chan bool)
	aliceSentChan := make(chan bool)
	aliceDeliveredChan := make(chan bool)

	go func() {
		sentEventSeenIds := make(map[MessageID]bool)
		for {
			ev, ok := <-alice.EventSink
			if !ok {
				return
			}
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				alice.log.Debugf("CSTDSR: ALICE GOT KEYEX COMPLETED")
				require.Nil(event.Err)
				aliceKXFinishedChan <- true
				break
			case *MessageDeliveredEvent:
				alice.log.Debugf("CSTDSR: ALICE GOT DELIVERED EVENT")
				require.Equal(event.Nickname, "bob")
				aliceDeliveredChan <- true
			case *MessageSentEvent:
				if _, ok = sentEventSeenIds[event.MessageID]; ok {
					alice.log.Debugf("CSTDSR: ALICE GOT DUPE SENT MESSAGE %x to %s", event.MessageID, event.Nickname)
					continue
				}
				alice.log.Debugf("CSTDSR: ALICE SENT MESSAGE %x to %s", event.MessageID, event.Nickname)
				require.Equal(event.Nickname, "bob")
				aliceSentChan <- true
			default:
				alice.log.Debugf("CSTDSR: ALICE EVENTSINK GOT EVENT %t", ev)
			}
		}
	}()

	<-bobKXFinishedChan
	<-aliceKXFinishedChan

	alice.SendMessage("bob", []byte(`Data encryption is used widely to protect the content of Internet
communications and enables the myriad of activities that are popular today,
from online banking to chatting with loved ones. However, encryption is not
sufficient to protect the meta-data associated with the communications.
`))
	<-aliceSentChan
	<-aliceDeliveredChan
	<-bobReceivedMessageChan

	alice.log.Debugf("CSTDSR: ALICE SENDING SECOND MESSAGE to bob")
	alice.SendMessage("bob", []byte(`Since 1979, there has been active academic research into communication
meta-data protection, also called anonymous communication networking, that has
produced various designs. Of these, mix networks are among the most practical
and can readily scale to millions of users.
`))
	<-aliceSentChan
	<-aliceDeliveredChan
	<-bobReceivedMessageChan

	// Test statefile persistence of conversation.

	alice.log.Debug("LOADING ALICE'S CONVERSATION")
	aliceConvesation := alice.conversations["bob"]
	for i, mesg := range aliceConvesation {
		alice.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	// Test sorted conversation and message delivery status
	aliceSortedConvesation := alice.GetSortedConversation("bob")
	for _, msg := range aliceSortedConvesation {
		require.True(msg.Sent)
		require.True(msg.Delivered)
	}

	bob.log.Debug("LOADING BOB'S CONVERSATION")
	bobConvesation := bob.conversations["alice"]
	for i, mesg := range bobConvesation {
		bob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	alice.Shutdown()
	bob.Shutdown()
	err = copyFile(aliceStateFilePath, "testdata/alice_state")
	require.NoError(err)
	err = copyFile(bobStateFilePath, "testdata/bob_state")
	require.NoError(err)
	bob.log.Debug("copied state")

/*
	newAlice := reloadCatshadowState(t, aliceStateFilePath)
	newAlice.log.Debug("LOADING ALICE'S CONVERSATION WITH BOB")
	aliceConvesation = newAlice.conversations["bob"]
	for i, mesg := range aliceConvesation {
		newAlice.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	newBob := reloadCatshadowState(t, bobStateFilePath)
	newBob.log.Debug("LOADING BOB'S CONVERSATION WITH ALICE")
	bobConvesation = newBob.conversations["alice"]
	for i, mesg := range bobConvesation {
		newBob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	newMal := reloadCatshadowState(t, malStateFilePath)
	newMal.log.Debug("LOADING MAL'S CONVERSATION WITH BOB")
	malBobConversation := newMal.conversations["bob"]
	for i, mesg := range malBobConversation {
		newMal.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
		if !mesg.Outbound {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello mal`)))
		} else {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello bob`)))
		}
	}

	newBob.log.Debug("LOADING BOB'S CONVERSATION WITH MAL")
	bobMalConversation := newBob.conversations["mal"]
	for i, mesg := range bobMalConversation {
		newBob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
		if !mesg.Outbound {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello bob`)))
		} else {
			require.True(bytes.Equal(mesg.Plaintext, []byte(`Hello mal`)))
		}
	}

	newAliceState := getClientState(newAlice)
	aliceState := getClientState(alice)
	aliceBobConvo1 := aliceState.Conversations["bob"]
	aliceBobConvo2 := newAliceState.Conversations["bob"]

	time.Sleep(3 * time.Second)

	require.NotNil(aliceBobConvo1)
	require.NotNil(aliceBobConvo2)
	newAlice.log.Debug("convo1\n")
	for i, message := range aliceBobConvo1 {
		require.True(bytes.Equal(message.Plaintext, aliceBobConvo2[i].Plaintext))
		// XXX require.True(message.Timestamp.Equal(aliceBobConvo2[i].Timestamp))
	}
	newAlice.Shutdown()
	newBob.Shutdown()
*/
}

func TestUpgradeResume(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// if testdata/alice_state exists, load it, otherwise, create it
	// if testdata/bob_state exists, load it, otherwise, create it
	var alice, bob *Client
	_, aErr := os.Open("testdata/alice_state")
	_, bErr := os.Open("testdata/bob_state")
	if aErr == nil && bErr == nil {
	} else {
		// create 2 statefiles for a pair of contacts
		aliceStateFilePath := createRandomStateFile(t)
		alice := createCatshadowClientWithState(t, aliceStateFilePath)
		bobStateFilePath := createRandomStateFile(t)
		bob := createCatshadowClientWithState(t, bobStateFilePath)

		sharedSecret := []byte("wait for key exchange")
		randBytes := [8]byte{}
		_, err := rand.Reader.Read(randBytes[:])
		require.NoError(err)
		sharedSecret = append(sharedSecret, randBytes[:]...)

		alice.NewContact("bob", sharedSecret)
		bob.NewContact("alice", sharedSecret)

		ctx, _ /*cancelFn*/ := context.WithTimeout(context.Background(), time.Minute)
		evt := waitForEvent(ctx,  alice.EventSink, &KeyExchangeCompletedEvent{})
		ev, ok := evt.(*KeyExchangeCompletedEvent)
		require.True(ok)
		require.NoError(ev.Err)

		ctx, _ /*cancelFn*/ = context.WithTimeout(context.Background(), time.Minute)
		evt = waitForEvent(ctx, bob.EventSink, &KeyExchangeCompletedEvent{})
		ev, ok = evt.(*KeyExchangeCompletedEvent)
		require.True(ok)
		require.NoError(ev.Err)

		// save the statefiles.
		alice.Shutdown()
		bob.Shutdown()

		err = copyFile(aliceStateFilePath, "testdata/alice_state")
		require.NoError(err)
		err = copyFile(bobStateFilePath, "testdata/bob_state")
		require.NoError(err)
	}
	alice = reloadCatshadowState(t, "testdata/alice_state")
	bob = reloadCatshadowState(t, "testdata/bob_state")

	bob.SendMessage("alice", []byte("blah"))

	ctx, _ /*cancelFn*/ := context.WithTimeout(context.Background(), time.Minute)
	evt := waitForEvent(ctx,  alice.EventSink, &MessageReceivedEvent{})
	ev, ok := evt.(*MessageReceivedEvent)
	require.True(ok)
	require.Equal(ev.Nickname, "bob")
}

