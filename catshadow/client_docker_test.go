// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
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
	"bytes"
	"context"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"net/http"
	_ "net/http/pprof"
	"runtime"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
)

func copyFile(src string, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(dst, data, 0644)
	return err
}

func getClientState(c *Client) *State {
	contacts := []*Contact{}
	for _, contact := range c.contacts {
		contacts = append(contacts, contact)
	}
	return &State{
		SpoolReadDescriptor: c.spoolReadDescriptor,
		Contacts:            contacts,
		Conversations:       c.conversations,
	}
}

func createCatshadowClientWithState(t *testing.T, stateFile string) *Client {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	var stateWorker *StateWriter
	var catShadowClient *Client

	//cfg.Logging.Level = "INFO" // client verbosity reductionism
	c, err := client.New(cfg)
	require.NoError(err)
	passphrase := []byte("")
	stateWorker, err = NewStateWriter(c.GetLogger("catshadow_state"), stateFile, passphrase)
	require.NoError(err)
	// must start stateWorker BEFORE calling NewClientAndRemoteSpool
	stateWorker.Start()
	backendLog, err := log.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	require.NoError(err)
	catShadowClient, err = NewClientAndRemoteSpool(context.Background(), backendLog, c, stateWorker)
	require.NoError(err)

	return catShadowClient
}

func reloadCatshadowState(t *testing.T, stateFile string) *Client {
	require := require.New(t)

	// Load catshadow config file.
	cfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	var stateWorker *StateWriter
	var catShadowClient *Client

	passphrase := []byte("")
	key := stretchKey(passphrase)
	state, err := decryptStateFile(stateFile, key)
	require.NoError(err)

	logBackend, err := log.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	require.NoError(err)
	c, err := client.New(cfg)
	require.NoError(err)
	stateWorker, state, err = LoadStateWriter(c.GetLogger(stateFile), stateFile, passphrase)
	require.NoError(err)

	catShadowClient, err = New(logBackend, c, stateWorker, state)
	require.NoError(err)

	// Start catshadow client.
	stateWorker.Start()
	catShadowClient.Start()

	// Bring catshadow online
	catShadowClient.Online(context.Background())

	return catShadowClient
}

func waitForEvent(ctx context.Context, eventCh chan interface{}, eventType interface{}) interface{} {
	for {
		select {
		case ev := <-eventCh:
			if reflect.TypeOf(ev) == reflect.TypeOf(eventType) {
				return ev
			}
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func TestWaitForEvent(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	aliceState := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceState)
	bobState := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobState)

	sharedSecret := []byte("wait for key exchange")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	ctx, _ /*cancelFn*/ := context.WithTimeout(context.Background(), time.Minute)
	evt := waitForEvent(ctx, alice.EventSink, &KeyExchangeCompletedEvent{})
	ev, ok := evt.(*KeyExchangeCompletedEvent)
	require.True(ok)
	require.NoError(ev.Err)
}

func TestDockerPandaSuccess(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	aliceState := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceState)
	bobState := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobState)

	sharedSecret := []byte("There is a certain kind of small town that grows like a boil on the ass of every Army base in the world.")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

loop1:
	for {
		ev := <-alice.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

loop2:
	for {
		ev := <-bob.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	alice.Shutdown()
	bob.Shutdown()
}

func TestDockerPandaTagContendedError(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceStateFilePath)
	bobStateFilePath := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobStateFilePath)

	sharedSecret := []byte("twas brillig and the slithy toves")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

loop1:
	for {
		ev := <-alice.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

loop2:
	for {
		ev := <-bob.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	alice.Shutdown()
	bob.Shutdown()

	// second phase of test, use same panda shared secret
	// in order to test that it invokes a tag contended error
	adaState := createRandomStateFile(t)
	ada := createCatshadowClientWithState(t, adaState)
	jeffState := createRandomStateFile(t)
	jeff := createCatshadowClientWithState(t, jeffState)

	ada.NewContact("jeff", sharedSecret)
	jeff.NewContact("ada", sharedSecret)

loop3:
	for {
		ev := <-ada.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.NotNil(event.Err)
			break loop3
		default:
		}
	}

loop4:
	for {
		ev := <-jeff.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.NotNil(event.Err)
			break loop4
		default:
		}
	}

	ada.Shutdown()
	jeff.Shutdown()
}

func TestDockerSendReceive(t *testing.T) {
	require := require.New(t)

	aliceStateFilePath := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceStateFilePath)
	bobStateFilePath := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobStateFilePath)
	malStateFilePath := createRandomStateFile(t)
	mal := createCatshadowClientWithState(t, malStateFilePath)

	sharedSecret := []byte(`oxcart pillage village bicycle gravity socks`)
	sharedSecret2 := make([]byte, len(sharedSecret))
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	_, err = rand.Reader.Read(sharedSecret2[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	// bob has 2 contacts
	bob.NewContact("alice", sharedSecret)
	bob.NewContact("mal", sharedSecret2)
	mal.NewContact("bob", sharedSecret2)

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

	malKXFinishedChan := make(chan bool)
	malSentChan := make(chan bool)
	malReceivedMessageChan := make(chan bool)
	malDeliveredChan := make(chan bool)

	go func() {
		sentEventSeenIds := make(map[MessageID]bool)
		for {
			ev, ok := <-mal.EventSink
			if !ok {
				return
			}
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				mal.log.Debugf("CSTDSR: MAL GOT KEYEX COMPLETED")
				require.Nil(event.Err)
				malKXFinishedChan <- true
			case *MessageReceivedEvent:
				// fields: Nickname, Message, Timestamp
				require.Equal(event.Nickname, "bob")
				mal.log.Debugf("CSTDSR: MAL RECEIVED MESSAGE:\n%s", string(event.Message))
				malReceivedMessageChan <- true
			case *MessageDeliveredEvent:
				mal.log.Debugf("CSTDSR: MAL GOT DELIVERED EVENT")
				require.Equal(event.Nickname, "bob")
				malDeliveredChan <- true
			case *MessageSentEvent:
				if _, ok = sentEventSeenIds[event.MessageID]; ok {
					mal.log.Debugf("CSTDSR: MAL GOT DUPE SENT MESSAGE %x to %s", event.MessageID, event.Nickname)
					continue
				}
				mal.log.Debugf("CSTDSR: MAL SENT MESSAGE %x to %s", event.MessageID, event.Nickname)
				require.Equal(event.Nickname, "bob")
				malSentChan <- true

			default:
				mal.log.Debugf("CSTDSR: MAL EVENTSINK GOT EVENT %t", ev)
			}
		}
	}()

	<-bobKXFinishedChan
	<-aliceKXFinishedChan
	<-malKXFinishedChan
	<-bobKXFinishedChan
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

	mal.SendMessage("bob", []byte(`Hello bob`))
	<-malSentChan
	<-malDeliveredChan
	<-bobReceivedMessageChan

	// bob replies to mal
	bob.SendMessage("mal", []byte(`Hello mal`))
	<-bobSentChan
	<-bobDeliveredChan
	<-malReceivedMessageChan

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

	mal.log.Debug("LOADING MAL'S CONVERSATION")
	malConvesation := mal.conversations["bob"]
	for i, mesg := range malConvesation {
		bob.log.Debugf("%d outbound %v message:\n%s\n", i, mesg.Outbound, mesg.Plaintext)
	}

	alice.Shutdown()
	bob.Shutdown()
	mal.Shutdown()

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
}

func TestDockerReunionSuccess(t *testing.T) {
	t.Skip("Reunion does not work with 2KB payloads")
	t.Parallel()
	require := require.New(t)

	aliceState := createRandomStateFile(t)
	alice := createCatshadowClientWithState(t, aliceState)

	bobState := createRandomStateFile(t)
	bob := createCatshadowClientWithState(t, bobState)

	sharedSecret := []byte("There is a certain kind of small town that grows like a boil on the ass of every Army base in the world.")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	//for i:=0; i<10; i++ {
	//	go func() {
	//		malState := createRandomStateFile(t)
	//		mal := createCatshadowClientWithState(t, malState)
	//		antifaState := createRandomStateFile(t)
	//		antifa := createCatshadowClientWithState(t, antifaState)
	//		randBytes := [8]byte{}
	//		rand.Reader.Read(randBytes[:])

	//		go func() {mal.NewContact("antifa", randBytes[:])}()
	//		go func() {antifa.NewContact("mal", randBytes[:])}()
	//	}()
	//}
	afails := 0
	bfails := 0

loop1:
	for {
		ev := <-alice.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			// XXX: we do multiple exchanges, some will fail
			alice.log.Debugf("reunion ALICE RECEIVED event: %v\n", event)
			if event.Err != nil {
				afails++
				require.True(afails < 6)
				continue
			} else {
				break loop1
			}
		default:
		}
	}

loop2:
	for {
		ev := <-bob.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			// XXX: we do multiple exchanges, some will fail
			bob.log.Debugf("reunion BOB RECEIVED event: %v\n", event)
			if event.Err != nil {
				bfails++
				require.True(bfails < 6)
				continue
			} else {
				break loop2
			}
		default:
		}
	}

	alice.Shutdown()
	bob.Shutdown()
}

func TestDockerChangeExpiration(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	a := createCatshadowClientWithState(t, createRandomStateFile(t))

	s := [8]byte{}
	_, err := rand.Reader.Read(s[:])
	require.NoError(err)

	a.NewContact("b", s[:])
	exp, err := a.GetExpiration("b")
	require.NoError(err)
	require.Equal(exp, MessageExpirationDuration)
	err = a.ChangeExpiration("b", time.Duration(123))
	require.NoError(err)
	exp, err = a.GetExpiration("b")
	require.NoError(err)
	require.Equal(exp, time.Duration(123))
	_, err = a.GetExpiration("c")
	require.Error(err, ErrContactNotFound)

}

func TestDockerAddRemoveContact(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	a := createCatshadowClientWithState(t, createRandomStateFile(t))
	b := createCatshadowClientWithState(t, createRandomStateFile(t))

	s := [8]byte{}
	_, err := rand.Reader.Read(s[:])
	require.NoError(err)

	a.NewContact("b", s[:])
	b.NewContact("a", s[:])

loop1:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

loop2:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	t.Log("Sending message to b")
	a.SendMessage("b", []byte{0})
loop3:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			t.Log("Message delivered to b")
			if event.Nickname == "b" {
				break loop3
			} else {
				t.Log(event)
			}
		default:
		}
	}

	t.Log("Sending message to a")
	b.SendMessage("a", []byte{0})

loop4:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			t.Log("Message delivered to a")
			if event.Nickname == "a" {
				break loop4
			}
		default:
		}
	}

	t.Log("Removing contact b")
	err = a.RemoveContact("b")
	require.NoError(err)
	require.Equal(len(a.GetContacts()), 0)

	t.Log("Removing contact b again, checking for err")
	err = a.RemoveContact("b")
	require.Error(err, ErrContactNotFound)

	a.conversationsMutex.Lock()
	c := a.conversations["b"]
	require.Equal(len(c), 0)
	a.conversationsMutex.Unlock()

	// verify that contact data is gone
	t.Log("Sending message to b, must fail")
	a.SendMessage("b", []byte("must fail"))
loop5:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageNotSentEvent:
			if event.Nickname == "b" {
				break loop5
			}
		default:
		}
	}

	a.Shutdown()
	b.Shutdown()
}

func TestDockerRenameContact(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	a := createCatshadowClientWithState(t, createRandomStateFile(t))
	b := createCatshadowClientWithState(t, createRandomStateFile(t))

	s := [8]byte{}
	_, err := rand.Reader.Read(s[:])
	require.NoError(err)

	a.NewContact("b", s[:])
	b.NewContact("a", s[:])

	// wait for key exchanges to complete
loop1:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

loop2:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	t.Log("Sending message to b")
	a.SendMessage("b", []byte("a->b"))
	// wait for message to be delivered to spool
loop3:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			t.Log("Message delivered to b")
			if event.Nickname == "b" {
				break loop3
			} else {
				t.Log(event)
			}
		default:
		}
	}

	// wait for message to be received by b
loop3a:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *MessageReceivedEvent:
			t.Log("Message received by b")
			if event.Nickname == "a" {
				break loop3a
			}
		default:
		}
	}
	t.Log("Sending message to a")
	b.SendMessage("a", []byte("b->a"))
	// wait for message to be delivered to spool
loop4:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			t.Log("Message delivered to a")
			if event.Nickname == "a" {
				break loop4
			}
		default:
		}
	}
	// wait for message to be received by a
loop4a:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageReceivedEvent:
			t.Log("Message received by a")
			if event.Nickname == "b" {
				break loop4a
			}
		default:
		}
	}

	// rename the contacts
	t.Log("Renaming contact b")
	err = a.RenameContact("b", "b2")
	require.NoError(err)

	// XXX: a.conversations["b"] - panics with bad map state
	a.conversationsMutex.Lock()
	c := a.conversations["b"]
	a.conversationsMutex.Unlock()
	require.Equal(len(c), 0)

	// verify that contact data is gone
	t.Log("Sending message to b, must fail")
	a.SendMessage("b", []byte("must fail"))

	// wait for failure sending message
loop5:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageNotSentEvent:
			if event.Nickname == "b" {
				break loop5
			}
		default:
		}
	}

	// send message to the renamed contact
	a.SendMessage("b2", []byte("a->b2"))
	// wait for message to be delivered to spool
loop6:
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			t.Log("Message delivered to b2")
			if event.Nickname == "b2" {
				break loop6
			} else {
				t.Log(event)
			}
		default:
		}
	}
	// wait for message to be received by b
loop7:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *MessageReceivedEvent:
			t.Log("Message received by b2")
			if event.Nickname == "a" {
				break loop7
			} else {
				t.Log(event)
			}
		default:
		}
	}

	// verify that b2 has sent 1 message and received 2 messages
	c = b.conversations["a"]

	sent := 0
	received := 0
	for _, msg := range c {
		if msg.Sent {
			sent += 1
		} else {
			received += 1
		}
	}
	require.Equal(1, sent)
	require.Equal(2, received)
	require.Equal(1, len(a.conversations))
	require.Equal(1, len(b.conversations))

	// clear conversation history
	b.WipeConversation("a")
	c = b.conversations["a"]
	require.Equal(len(c), 0)

	a.Shutdown()
	b.Shutdown()
}

func init() {
	go func() {
		http.ListenAndServe("localhost:8080", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}
