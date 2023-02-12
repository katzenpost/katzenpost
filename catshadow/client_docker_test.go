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
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
	"net/http"
	_ "net/http/pprof"
	"runtime"
)

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
	catShadowClient, err = NewClientAndRemoteSpool(backendLog, c, stateWorker)
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
	catShadowClient.Online()

	return catShadowClient
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
			t.Logf("loop3: %T %+v", event, ev)
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
	t.Parallel()
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
		for {
			ev, ok := <-bob.EventSink
			if !ok {
				return
			}
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				require.Nil(event.Err)
				bobKXFinishedChan <- true
			case *MessageReceivedEvent:
				// fields: Nickname, Message, Timestamp
				bob.log.Debugf("BOB RECEIVED MESSAGE from %s:\n%s", event.Nickname, string(event.Message))
				bobReceivedMessageChan <- true
			case *MessageDeliveredEvent:
				require.Equal(event.Nickname, "mal")
				bobDeliveredChan <- true
			case *MessageSentEvent:
				bob.log.Debugf("BOB SENT MESSAGE to %s", event.Nickname)
				require.Equal(event.Nickname, "mal")
				bobSentChan <- true
			default:
			}
		}
	}()

	aliceKXFinishedChan := make(chan bool)
	aliceSentChan := make(chan bool)
	aliceDeliveredChan := make(chan bool)
	go func() {
		for {
			ev, ok := <-alice.EventSink
			if !ok {
				return
			}
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				require.Nil(event.Err)
				aliceKXFinishedChan <- true
				break
			case *MessageSentEvent:
				alice.log.Debugf("ALICE SENT MESSAGE to %s", event.Nickname)
				require.Equal(event.Nickname, "bob")
				aliceSentChan <- true
			case *MessageDeliveredEvent:
				require.Equal(event.Nickname, "bob")
				aliceDeliveredChan <- true
			default:
			}
		}
	}()

	malKXFinishedChan := make(chan bool)
	malSentChan := make(chan bool)
	malReceivedMessageChan := make(chan bool)
	malDeliveredChan := make(chan bool)
	go func() {
		for {
			ev, ok := <-mal.EventSink
			if !ok {
				return
			}
			switch event := ev.(type) {
			case *KeyExchangeCompletedEvent:
				require.Nil(event.Err)
				malKXFinishedChan <- true
			case *MessageReceivedEvent:
				// fields: Nickname, Message, Timestamp
				require.Equal(event.Nickname, "bob")
				mal.log.Debugf("MAL RECEIVED MESSAGE:\n%s", string(event.Message))
				malReceivedMessageChan <- true
			case *MessageDeliveredEvent:
				require.Equal(event.Nickname, "bob")
				malDeliveredChan <- true
			case *MessageSentEvent:
				mal.log.Debugf("MAL SENT MESSAGE to %s", event.Nickname)
				require.Equal(event.Nickname, "bob")
				malSentChan <- true

			default:
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

	c := a.conversations["b"]
	require.Equal(len(c), 0)
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
loop3: // wait for "a->b" to be delivered
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			if event.Nickname == "b" {
				t.Log("Message delivered to b")
				break loop3
			} else {
				t.Log(event)
				panic("who the hell did we MessageDeliveredEvent to")
			}
		case *MessageNotSentEvent:
			t.Log(event)
			panic("MessageNotSent {a->b}")
		case *MessageNotDeliveredEvent:
			t.Log(event)
			panic("MessageNotDeliveredEvent {a->b}")
		default:
			t.Logf("loop3: %T %+v", ev, ev)
			panic("loop3 received some unknown stuff")
		}
	}

	t.Log("Sending message to a")
	b.SendMessage("a", []byte("b->a"))

loop4: // wait for "b->a" to be delivered
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			if event.Nickname == "a" {
			t.Log("loop4:Message delivered to a")
				break loop4
			}
			t.Log(event)
			panic("loop4:who the hell got b->a?")
		case *MessageNotSentEvent:
			t.Log("loop4:", event)
			panic("loop4:MessageNotSent {b->a}")
		case *MessageNotDeliveredEvent:
			t.Log("loop4", event)
			panic("loop4:MessageNotDeliveredEvent {b->a}")
		default:
			t.Logf("%T %+v", event, ev)
			panic("loop4: default")
		}
	}

	c0 := len(a.conversations["b"])
	t.Logf("Renaming contact b to b2, len(a.conversations[b]): %v", c0)
	err = a.RenameContact("b", "b2")
	require.NoError(err)

	c := a.conversations["b"]
	require.Equal(len(c), 0)
	// should have old conversations under new name:
	require.Equal(c0, len(a.conversations["b2"]))

	// verify that contact data is gone
	t.Log("Sending message to b, must fail")
	a.SendMessage("b", []byte("must fail"))

loop5: // wait for a->b: "must fail" to fail because b is now called b2
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageNotSentEvent:
			if event.Nickname == "b" {
				break loop5
			} else {
				t.Logf("loop5:MNSE: %+v", event)
			}
		default:
			t.Logf("loop5 %T %+v", event, event)
			panic("loop5: wait why didn't we get an error here")
		}
	}

	// send message to the renamed contact
	a.SendMessage("b2", []byte("a->b2"))
loop6: // wait for a->b2 to be delivered
	for {
		ev := <-a.EventSink
		switch event := ev.(type) {
		case *MessageDeliveredEvent:
			t.Log("loop6:Message delivered to b2")
			if event.Nickname == "b2" {
				break loop6
			} else {
				t.Log(event)
				panic("loop6: who did we deliver to")
			}
		case *MessageSentEvent:
			t.Log("loop6:Message sent but not delivered to b2 yet")
		case *MessageNotSentEvent:
			t.Log("loop6:Well that is too plain bad, MessageNotSent")
			panic("loop6:couldnt send message")
		case *MessageReceivedEvent:
			t.Logf("loop6:a:MessageReceivedEvent %+v", event)
			panic("loop6: MessageReceivedEvent")
		default:
			t.Logf("loop6:how we ended up here %T %s %T %s", event, event, ev, ev)
			panic("loop6:how did we end up here")
		}
	}
loop7:
	for {
		ev := <-b.EventSink
		switch event := ev.(type) {
		case *MessageReceivedEvent:
			t.Log("loop7:Message received by b2")
			if event.Nickname == "a" {
				break loop7
			} else {
				t.Log("loop7",event)
				panic("wait who sent that")
			}
		default:
			t.Log(event)
			panic("what the heck")
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
			if msg.Outbound {
				panic("Outbound but not Sent")
			}
			received += 1
		}
	}
	require.Equal(1, sent)

	//a.SendMessage("b", []byte("a->b")) // after loop2
	//b.SendMessage("a", []byte("b->a")) // after loop3
	// after loop 4 and renaming b->b2:
	// a.SendMessage("b", []byte("must fail")) // but "b" no longer exists
	// a.SendMessage("b2", []byte("a->b2"))
	// so at this point:
	// "a" should have sent 2 valid messages to "b"/"b2"
	// "a" should have received 1 message from "a"
	// "b" should have sent 1 valid message to "a"
	// "b" should have received 2 messages from "a"

	if received > 2 {
		t.Logf("Retransmission of message detected")
		var last *Message
		for _, msg := range c {
			if last == nil {
				last = msg
			} else {
				if bytes.Equal(last.Plaintext, msg.Plaintext) {
					t.Logf("%s was retransmitted", last.Plaintext)
				}
			}
		}
	} else {
		require.Equal(2, received)
	}

	// clear conversation history
	b.WipeConversation("a")
	c = b.conversations["a"]
	require.Equal(0, len(c))

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
